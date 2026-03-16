using Amazon.Lambda.Core;
using Amazon.Scheduler;
using Amazon.Scheduler.Model;
using Oci.Common;
using Oci.Common.Auth;
using Oci.CoreService;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using System.Text.Json;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace OpenSshIpOci;

public class Function
{
    private static readonly string SUBNET_ID = Environment.GetEnvironmentVariable("OCI_SUBNET_ID") ?? throw new InvalidOperationException("OCI_SUBNET_ID is not set");
    private static readonly string COMPONET_ID = Environment.GetEnvironmentVariable("OCI_COMPARTMENT_ID") ?? throw new InvalidOperationException("OCI_COMPARTMENT_ID is not set");
    private static readonly string VCN_ID = Environment.GetEnvironmentVariable("OCI_VCN_ID") ?? throw new InvalidOperationException("OCI_VCN_ID is not set");
    private static readonly string USER_ID = Environment.GetEnvironmentVariable("OCI_USER_ID") ?? throw new InvalidOperationException("OCI_USER_ID is not set");
    private static readonly string FINGERPRINT = Environment.GetEnvironmentVariable("OCI_FINGERPRINT") ?? throw new InvalidOperationException("OCI_FINGERPRINT is not set");
    private static readonly string TENANCY_ID = Environment.GetEnvironmentVariable("OCI_TENANCY_ID") ?? throw new InvalidOperationException("OCI_TENANCY_ID is not set");
    private static readonly string PRIVATE_KEY = Environment.GetEnvironmentVariable("OCI_PRIVATE_KEY") ?? throw new InvalidOperationException("OCI_PRIVATE_KEY is not set");

    /*
      {
        "IPv4" : "192.0.2.1",
        "IPv6" : "2001:db8:0:0:3020:d5dd:7a17:eb70"
       }
     */

    /// <summary>
    /// A simple function that takes a string and does a ToUpper
    /// </summary>
    /// <param name="input">The event for the Lambda function handler to process.</param>
    /// <param name="context">The ILambdaContext that provides methods for logging and describing the Lambda environment.</param>
    /// <returns></returns>
    public async Task<string> FunctionHandlerAsync(JsonElement input, ILambdaContext context)
    {
        string ipv4 = input.GetProperty("IPv4").GetString() ?? string.Empty;
        string ipv6 = input.GetProperty("IPv6").GetString() ?? string.Empty;
        string ipV6WithoutMac = string.Empty;
        if (!string.IsNullOrEmpty(ipv6))
        {
            string[] ipv6Split = ipv6.Split(":");
            ipV6WithoutMac = $"{ipv6Split[0]}:{ipv6Split[1]}:{ipv6Split[2]}:{ipv6Split[3]}::";
        }

        var provider = new SimpleAuthenticationDetailsProvider
        {
            UserId = USER_ID,
            Fingerprint = FINGERPRINT,
            TenantId = TENANCY_ID,
            Region = Oci.Common.Region.AP_TOKYO_1,
            PrivateKeySupplier = new StringPrivateKeySupplier(PRIVATE_KEY)
        };

        //追加するセキュリティリストを作成
        var createSecurityListDetails = new CreateSecurityListDetails
        {
            CompartmentId = COMPONET_ID,
            DisplayName = $"ssh_temp_{DateTime.Now:yyyyMMddHHmmss}",
            IngressSecurityRules =
            [
                new IngressSecurityRule
                    {
                        Protocol = "6",
                        Source = $"{ipv4}/32",
                        SourceType = IngressSecurityRule.SourceTypeEnum.CidrBlock,
                        TcpOptions = new TcpOptions
                        {
                            DestinationPortRange = new PortRange
                            {
                                Max = 22,
                                Min = 22
                            }
                        }
                    }
            ],
            EgressSecurityRules = new List<EgressSecurityRule> { },
            VcnId = VCN_ID
        };

        //IPv6アドレスも取得できていれば追加
        createSecurityListDetails.IngressSecurityRules.Add(new IngressSecurityRule()
        {
            Protocol = "6",
            Source = $"{ipV6WithoutMac}/64",
            SourceType = IngressSecurityRule.SourceTypeEnum.CidrBlock,
            TcpOptions = new TcpOptions
            {
                DestinationPortRange = new PortRange
                {
                    Max = 22,
                    Min = 22
                }
            }
        });

        //セキュリティリストを作成
        var createSecurityListRequest = new CreateSecurityListRequest
        {
            CreateSecurityListDetails = createSecurityListDetails,
        };
        VirtualNetworkClient client = new(provider, new ClientConfiguration());
        string createdSlistId = string.Empty;
        var response = await client.CreateSecurityList(createSecurityListRequest);
        createdSlistId = response.SecurityList.Id;

        //アタッチするサブネットを取得
        var getSubnetRequest = new GetSubnetRequest
        {
            SubnetId = SUBNET_ID
        };
        var subnetResponse = await client.GetSubnet(getSubnetRequest);
        var subnet = subnetResponse.Subnet;

        //サブネットにセキュリティリストを追加
        subnet.SecurityListIds.Add(createdSlistId);

        //サブネットを更新
        var updateSubnetRequest = new UpdateSubnetRequest
        {
            SubnetId = subnet.Id,
            UpdateSubnetDetails = new UpdateSubnetDetails { SecurityListIds = subnet.SecurityListIds },
        };
        await client.UpdateSubnet(updateSubnetRequest);

        string? closeArn = Environment.GetEnvironmentVariable("CLOSE_FUNCTION_ARN");
        if (!string.IsNullOrWhiteSpace(closeArn))
        {
            // EventBridge Schedulerに削除ジョブを登録
            var runAt = DateTime.UtcNow.AddMinutes(120).ToString("yyyy-MM-ddTHH:mm:ss");
            var scheduler = new AmazonSchedulerClient();
            await scheduler.CreateScheduleAsync(new CreateScheduleRequest
            {
                Name = $"close-ssh-{createdSlistId}",
                ScheduleExpression = $"at({runAt})",
                ScheduleExpressionTimezone = "UTC",
                FlexibleTimeWindow = new FlexibleTimeWindow { Mode = FlexibleTimeWindowMode.OFF },
                ActionAfterCompletion = ActionAfterCompletion.DELETE,
                Target = new Target
                {
                    Arn = closeArn,
                    RoleArn = Environment.GetEnvironmentVariable("SCHEDULER_ROLE_ARN"),
                    Input = System.Text.Json.JsonSerializer.Serialize(new { security_list_id = createdSlistId })
                }
            });
        }

        return string.Empty;
    }
}

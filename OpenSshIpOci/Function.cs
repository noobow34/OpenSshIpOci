using Amazon.Lambda.APIGatewayEvents;
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
    public async Task<APIGatewayProxyResponse> FunctionHandlerAsync(JsonElement input, ILambdaContext context)
    {
        context.Logger.LogInformation($"[START] RequestId={context.AwsRequestId}");

        try
        {
            string ipv4 = input.GetProperty("IPv4").GetString() ?? string.Empty;
            string ipv6 = input.GetProperty("IPv6").GetString() ?? string.Empty;
            context.Logger.LogInformation($"[INPUT] IPv4={ipv4}, IPv6={ipv6}");

            // IPv6 プレフィックス加工
            string ipV6WithoutMac = string.Empty;
            if (!string.IsNullOrEmpty(ipv6))
            {
                string[] ipv6Split = ipv6.Split(":");
                ipV6WithoutMac = $"{ipv6Split[0]}:{ipv6Split[1]}:{ipv6Split[2]}:{ipv6Split[3]}::";
                context.Logger.LogInformation($"[INPUT] IPv6 prefix={ipV6WithoutMac}");
            }

            // --- OCI 認証プロバイダー ---
            var provider = new SimpleAuthenticationDetailsProvider
            {
                UserId = USER_ID,
                Fingerprint = FINGERPRINT,
                TenantId = TENANCY_ID,
                Region = Oci.Common.Region.AP_TOKYO_1,
                PrivateKeySupplier = new StringPrivateKeySupplier(PRIVATE_KEY)
            };
            VirtualNetworkClient client = new(provider, new ClientConfiguration());

            // --- SecurityList 作成 ---
            context.Logger.LogInformation("[OCI] Creating SecurityList...");
            var ingressRules = new List<IngressSecurityRule>
            {
                new() {
                    Protocol   = "6",
                    Source     = $"{ipv4}/32",
                    SourceType = IngressSecurityRule.SourceTypeEnum.CidrBlock,
                    TcpOptions = new TcpOptions
                    {
                        DestinationPortRange = new PortRange { Max = 22, Min = 22 }
                    }
                }
            };
            if (!string.IsNullOrEmpty(ipV6WithoutMac))
            {
                ingressRules.Add(new IngressSecurityRule
                {
                    Protocol = "6",
                    Source = $"{ipV6WithoutMac}/64",
                    SourceType = IngressSecurityRule.SourceTypeEnum.CidrBlock,
                    TcpOptions = new TcpOptions
                    {
                        DestinationPortRange = new PortRange { Max = 22, Min = 22 }
                    }
                });
            }
            var createSecurityListDetails = new CreateSecurityListDetails
            {
                CompartmentId = COMPONET_ID,
                DisplayName = $"ssh_temp_{DateTime.Now:yyyyMMddHHmmss}",
                IngressSecurityRules = ingressRules,
                EgressSecurityRules = new List<EgressSecurityRule>(),
                VcnId = VCN_ID
            };
            var createSecurityListRequest = new CreateSecurityListRequest
            {
                CreateSecurityListDetails = createSecurityListDetails
            };

            var createResponse = await client.CreateSecurityList(createSecurityListRequest);
            string createdSlistId = createResponse.SecurityList.Id;
            context.Logger.LogInformation($"[OCI] SecurityList created. Id={createdSlistId}");

            // --- Subnet 取得 ---
            context.Logger.LogInformation($"[OCI] Getting Subnet. SubnetId={SUBNET_ID}");
            var getSubnetRequest = new GetSubnetRequest { SubnetId = SUBNET_ID };
            var subnetResponse = await client.GetSubnet(getSubnetRequest);
            var subnet = subnetResponse.Subnet;
            context.Logger.LogInformation($"[OCI] Subnet retrieved. Name={subnet.DisplayName}");

            // --- Subnet 更新 ---
            context.Logger.LogInformation("[OCI] Updating Subnet...");
            subnet.SecurityListIds.Add(createdSlistId);
            var updateSubnetRequest = new UpdateSubnetRequest
            {
                SubnetId = subnet.Id,
                UpdateSubnetDetails = new UpdateSubnetDetails
                {
                    SecurityListIds = subnet.SecurityListIds
                }
            };
            await client.UpdateSubnet(updateSubnetRequest);
            context.Logger.LogInformation("[OCI] Subnet updated successfully.");

            // --- EventBridge Scheduler 登録 ---
            string? closeArn = Environment.GetEnvironmentVariable("CLOSE_FUNCTION_ARN");
            var runAt = DateTime.UtcNow.AddMinutes(120).ToString("yyyy-MM-ddTHH:mm:ss");
            if (!string.IsNullOrWhiteSpace(closeArn))
            {
                context.Logger.LogInformation($"[SCHEDULER] Registering close job. RunAt={runAt}, SecurityListId={createdSlistId}");

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
                        Input = JsonSerializer.Serialize(new { security_list_id = createdSlistId })
                    }
                });

                context.Logger.LogInformation("[SCHEDULER] Close job registered successfully.");
            }
            else
            {
                context.Logger.LogInformation("[SCHEDULER] CLOSE_FUNCTION_ARN not set. Skipping scheduler registration.");
            }

            // --- 成功レスポンス ---
            context.Logger.LogInformation($"[SUCCESS] All steps completed. SecurityListId={createdSlistId}");

            return new APIGatewayProxyResponse
            {
                StatusCode = 200,
                Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } },
                Body = JsonSerializer.Serialize(new { security_list_id = createdSlistId, auto_close_at = runAt })
            };
        }
        catch (Exception ex)
        {
            context.Logger.LogError($"[ERROR] {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");

            var (statusCode, errorType) = ex switch
            {
                JsonException => (400, "Invalid JSON format"),
                KeyNotFoundException => (400, "Required parameter missing"),
                ArgumentException => (400, "Invalid argument"),
                UnauthorizedAccessException => (403, "Forbidden"),
                _ => (500, "Internal Server Error")
            };

            return new APIGatewayProxyResponse
            {
                StatusCode = statusCode,
                Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } },
                Body = JsonSerializer.Serialize(new
                {
                    error = errorType,
                    message = ex.Message,
                    requestId = context.AwsRequestId
                })
            };
        }
    }
}

using Twilio.Types;
using Twilio;
using Twilio.Rest.Api.V2010.Account;

namespace ASPNETCoreIdentityDemo.Models
{
    // interface
    public interface ISMSSender
    {
        Task<bool> SendSMSAsync(string message);
    }

    public class SMSSender : ISMSSender
    {
        private readonly IConfiguration _configuration;
        private readonly string AccounSID;
        private readonly string AuthToken;
        private readonly string FromNumber;

        public SMSSender(IConfiguration configuration)
        {
            _configuration = configuration;

            AccounSID = _configuration["SMSSettings:AccountSID"];
            AuthToken = _configuration["SMSSettings:AuthToken"];
            FromNumber = _configuration["SMSSettings:FromNumber"];
        }

        public Task<bool> SendSMSAsync(string message)
        {
            try
            {
                // Initialize base client AccountSID and Auth Token
                TwilioClient.Init(AccounSID, AuthToken);

                // Construct a new CreateMessageOptions
                var messageOptions = new CreateMessageOptions(new PhoneNumber(FromNumber))
                {
                    From = new PhoneNumber(FromNumber),
                    Body = message
                };

                // Send a message
                var msg = MessageResource.Create(messageOptions);

                // return true if no error
                return Task.FromResult(true);
            }
            catch(Exception ex)
            {
                // Log the Error Message and Return false
                return Task.FromResult(false);    
            }
        }
    }
}

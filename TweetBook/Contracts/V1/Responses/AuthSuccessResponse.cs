using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TweetBook.Contracts.V1.Responses
{
    public class AuthSuccessResponse
    {
        public string RefreshToken { get; set; }
        public string Token { get; set; }
    }
}

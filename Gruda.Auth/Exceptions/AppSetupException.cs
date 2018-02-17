using System;

namespace Gruda.Auth.Exceptions
{
    public class AppSetupException : Exception
    {
        public AppSetupException(string message) : base(message)
        {
        }

        public AppSetupException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}

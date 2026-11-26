using System;

namespace Tenzro.Sdk
{
    /// <summary>Raised when the node returns a JSON-RPC error or an unusable response.</summary>
    public sealed class TenzroRpcException : Exception
    {
        /// <summary>JSON-RPC error code, or 0 when the failure was not a JSON-RPC error object.</summary>
        public int Code { get; }

        /// <summary>An error the node answered with: its JSON-RPC <paramref name="code"/> and <paramref name="message"/>.</summary>
        public TenzroRpcException(int code, string message) : base(message) { Code = code; }
    }
}

// UNTESTED in a real Unity project. This is a plain C# script showing intended usage.
// It targets the netstandard2.1 build of Tenzro.Sdk, which compiles but has not been loaded into Unity.
// Not verified: Unity's runtime/IL2CPP behavior with System.Text.Json, HttpClient on all platforms (e.g. WebGL).
using System;
using System.Net.Http;
using System.Threading.Tasks;
using Tenzro.Sdk;
using UnityEngine;

public class TenzroBalanceBehaviour : MonoBehaviour
{
    public string rpcUrl = "http://127.0.0.1:28545";
    public string address = "0x0000000000000000000000000000000000000001";

    private HttpClient _http;

    private async void Start()
    {
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        var client = new TenzroClient(_http, new Uri(rpcUrl));
        try
        {
            Debug.Log($"Tenzro chain id: {await client.GetChainIdAsync()}");
            Debug.Log($"Balance: {await client.GetBalanceAsync(address)} wei");
        }
        catch (Exception e) { Debug.LogError(e); }
    }

    private void OnDestroy() => _http?.Dispose();
}

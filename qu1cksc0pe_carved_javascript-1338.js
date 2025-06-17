
        function decodeAndRunScript() {
            // This Base64 string is intentionally suspicious to test detection tools.
            var encodedScript = "Ly8gVGhpcyBpcyBhIGZha2UgbWFsaWNpb3VzIHNjcmlwdCBmb3IgdGVzdGluZyBwdXJwb3Nlcy4KZnVuY3Rpb24gZmFrZVBheWxvYWQoKSB7CiAgICB2YXIgdXNlciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd1c2VybmFtZScpLnZhbHVlOwogICAgdmFyIHBhc3MgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncGFzc3dvcmQnKS52YWx1ZTsKICAgIHZhciBjb21tYW5kID0gIldTY3JpcHQuU2hlbGwiOyAvLyBBIHN1c3BpY2lvdXMga2V5d29yZAogICAgdmFyIGRhdGEgPSAicGhpc2hpbmdfZGF0YT0iICsgdXNlciArICImcGFzcz0iICsgcGFzczsKICAgIC8vIFRoZSBmb2xsb3dpbmcgbGluZSB1c2VzICdldmFsJywgYW5vdGhlciBzdXNwaWNpb3VzIGtleXdvcmQuCiAgICBldmFsKCJjb25zb2xlLmxvZygnU2ltdWxhdGluZyBzZW5kaW5nIGRhdGE6ICcgKyBkYXRhKSk7CiAgICAvLyBBY2Nlc3NpbmcgY29va2llcyBpcyBhbHNvIHN1c3BpY2lvdXMuCiAgICB2YXIgeCA9IGRvY3VtZW50LmNvb2tpZTsKfQpjb25zb2xlLmxvZygiRGVjb2RlZCBzY3JpcHQgbG9hZGVkLiIpOw==";
            var decodedScript = atob(encodedScript);
            console.log("Decoded script content:", decodedScript);
            // Simulate the payload execution
            var script = document.createElement('script');
            script.innerHTML = decodedScript;
            document.head.appendChild(script);
            alert("This is a test. If this were real, your credentials would have been stolen!");
        }
    
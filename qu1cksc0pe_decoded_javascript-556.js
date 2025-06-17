// This is a fake malicious script for testing purposes.
function fakePayload() {
    var user = document.getElementById('username').value;
    var pass = document.getElementById('password').value;
    var command = "WScript.Shell"; // A suspicious keyword
    var data = "phishing_data=" + user + "&pass=" + pass;
    // The following line uses 'eval', another suspicious keyword.
    eval("console.log('Simulating sending data: ' + data));
    // Accessing cookies is also suspicious.
    var x = document.cookie;
}
console.log("Decoded script loaded.");
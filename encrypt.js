function deriveSecretKey(privateKey, publicKey) {
  return window.crypto.subtle.deriveKey(
    {name: "X25519", public: publicKey}, privateKey,
    {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"] ); }

async function encryptMessage(key, initializationVector, encodedMessage) {
  try {
    return await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: initializationVector },
      key, encodedMessage );
  } catch (e) {
    console.log(e);
    return `Encoding error`; } }

async function decryptMessage(key, initializationVector, ciphertext) {
  try {
    const decryptedText = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: initializationVector },
      key, ciphertext,
    );
    const utf8Decoder = new TextDecoder();
    return utf8Decoder.decode(decryptedText);
  } catch (e) {
    console.log(e);
    return "Decryption error"; } }

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i); }
  return buf; }

async function init() {
    const aliceKeyPair = await window.crypto.subtle.generateKey(
      {name: "X25519"}, true, ["deriveKey"] );
	exp = await window.crypto.subtle.exportKey('pkcs8', aliceKeyPair.privateKey)
	document.querySelector('#private-key').value = btoa(String.fromCharCode(...new Uint8Array(exp)));
	exp2 = await window.crypto.subtle.exportKey('spki', aliceKeyPair.publicKey)
	document.querySelector('#own-public-key').value = btoa(String.fromCharCode(...new Uint8Array(exp2)));

	document.querySelector('#message').addEventListener('change', function() {
 	 const reader = new FileReader();
  	 reader.onload = async function() {
       const iV = await window.crypto.getRandomValues(new Uint8Array(8));
       const ek = await window.crypto.subtle.importKey(
			"spki", str2ab(atob(document.querySelector('#public-key').value)),
			{"name": "X25519"}, false, [])
       const shared = await deriveSecretKey(aliceKeyPair.privateKey, ek);
	   const ciphertext = await encryptMessage(shared, iV, this.result)
	   const exp = await window.crypto.subtle.exportKey('raw', aliceKeyPair.publicKey)
       link = URL.createObjectURL(new Blob([exp, iV, ciphertext], {type:'application/octet-stream'}))
	   document.querySelector('#link').href = link
	   document.getElementById('link').classList.remove("off")
	 }
	 reader.readAsArrayBuffer(this.files[0]);
	}, false);

	document.querySelector('#message2').addEventListener('change', function() {
 	 const reader = new FileReader();
  	 reader.onload = async function() {
	   const iV = this.result.slice(32,40)
       const ciphertext = this.result.slice(40)
	   const pubkey = await window.crypto.subtle.importKey(
			"raw", this.result.slice(0,32), {"name": "X25519"}, false, [])
	   const prikey = await window.crypto.subtle.importKey(
			"pkcs8", str2ab(atob(document.querySelector('#private-key').value)), {"name": "X25519"}, false, ["deriveKey"])
       const shared = await deriveSecretKey(prikey, pubkey);
	   const cleartext = await decryptMessage(shared, iV, ciphertext);
       link = URL.createObjectURL(new Blob([cleartext], {type:'application/octet-stream'}))
	   document.querySelector('#link2').href = link
	   document.getElementById('link2').classList.remove("off")
	 }
	 reader.readAsArrayBuffer(this.files[0]);
	}, false); };

init();
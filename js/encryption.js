async function generateKeys() {
    const keyPair = await window.crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    localStorage.setItem("publicKey", btoa(String.fromCharCode(...new Uint8Array(publicKey))));
    localStorage.setItem("privateKey", btoa(String.fromCharCode(...new Uint8Array(privateKey))));

    alert("Keys Generated! You can now encrypt and decrypt messages.");
}

async function encryptMessage() {
    const publicKeyData = localStorage.getItem("publicKey");
    if (!publicKeyData) {
        alert("Generate keys first!");
        return;
    }

    const publicKeyBuffer = Uint8Array.from(atob(publicKeyData), c => c.charCodeAt(0)).buffer;
    const publicKey = await window.crypto.subtle.importKey("spki", publicKeyBuffer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);

    const message = document.getElementById("message").value;
    const encodedMessage = new TextEncoder().encode(message);
    const encryptedData = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, encodedMessage);

    document.getElementById("encrypted").innerText = btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
}

async function decryptMessage() {
    const privateKeyData = localStorage.getItem("privateKey");
    if (!privateKeyData) {
        alert("Generate keys first!");
        return;
    }

    const privateKeyBuffer = Uint8Array.from(atob(privateKeyData), c => c.charCodeAt(0)).buffer;
    const privateKey = await window.crypto.subtle.importKey("pkcs8", privateKeyBuffer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);

    const encryptedMessage = document.getElementById("encrypted").innerText;
    const encryptedBuffer = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0)).buffer;
    const decryptedData = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedBuffer);

    document.getElementById("decrypted").innerText = new TextDecoder().decode(decryptedData);
}

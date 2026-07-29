'use strict';

/**
 * Client-side encryption using Web Crypto API (AES-GCM 256-bit).
 * The server never sees the plaintext or the encryption key.
 */
const Crypto = (() => {
    const ALGORITHM = 'AES-GCM';
    const KEY_LENGTH = 256;
    const IV_LENGTH = 12;

    function arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCodePoint(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function base64UrlToArrayBuffer(base64url) {
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4 !== 0) { base64 += '='; }
        const binary = atob(base64);
        const buffer = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            buffer[i] = binary.codePointAt(i);
        }
        return buffer.buffer;
    }

    async function importKey(keyString) {
        return window.crypto.subtle.importKey(
            'raw',
            base64UrlToArrayBuffer(keyString),
            { name: ALGORITHM, length: KEY_LENGTH },
            false,
            ['decrypt']
        );
    }

    return {
        /** Generates a random encryption key and returns it as a URL-safe base64 string. */
        async generateKey() {
            const key = await window.crypto.subtle.generateKey(
                { name: ALGORITHM, length: KEY_LENGTH },
                true,
                ['encrypt', 'decrypt']
            );
            const exported = await window.crypto.subtle.exportKey('raw', key);
            return { cryptoKey: key, keyString: arrayBufferToBase64Url(exported) };
        },

        /** Encrypts plaintext with the given CryptoKey. Returns base64url(iv + ciphertext). */
        async encrypt(cryptoKey, plaintext) {
            const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
            const encoded = new TextEncoder().encode(plaintext);
            const ciphertext = await window.crypto.subtle.encrypt(
                { name: ALGORITHM, iv },
                cryptoKey,
                encoded
            );
            const combined = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(ciphertext), IV_LENGTH);
            return arrayBufferToBase64Url(combined.buffer);
        },

        /** Decrypts ciphertext (base64url encoded with prepended IV) using the given key string. */
        async decrypt(keyString, ciphertextB64) {
            const cryptoKey = await importKey(keyString);
            const combined = new Uint8Array(base64UrlToArrayBuffer(ciphertextB64));
            const iv = combined.slice(0, IV_LENGTH);
            const ciphertext = combined.slice(IV_LENGTH);
            const decrypted = await window.crypto.subtle.decrypt(
                { name: ALGORITHM, iv },
                cryptoKey,
                ciphertext
            );
            return new TextDecoder().decode(decrypted);
        }
    };
})();

// --- Vue 3 Components ---

const CreateSecret = {
    template: `
<div class="alert alert-success" role="alert" v-if="short_url">
  <p><b>Secret saved</b></p>
  <p>Send the following URL in one channel and the decryption key in another. Receiver will then be asked for the decryption key</p>
  URL: <a :href="short_url">{{ short_url }}</a><br/>
  Decryption Key: <b>{{ decryption_key }}</b>
</div>
<div class="jumbotron">
<form @submit.prevent>
  <div class="alert alert-danger" role="alert" v-if="error">{{ error }}</div>
  <div class="form-group">
    <textarea class="form-control" rows="3" v-model="secret" placeholder="Secret message"></textarea>
  </div>
  <div class="form-group" @click="options = true" v-if="!options" style="cursor:pointer">
    <span class="glyphicon glyphicon-triangle-bottom" aria-hidden="true"></span> Options
  </div>
  <div v-show="options">
    <label>Lifetime</label>
    <span class="help-block">Your secret will self destruct in...</span>
    <div class="radio">
      <label>
        <input type="radio" v-model="lifetime" value="1h">1 hour
      </label>
    </div>
    <div class="radio">
      <label>
        <input type="radio" v-model="lifetime" value="1d">1 day
      </label>
    </div>
    <div class="radio">
      <label>
        <input type="radio" v-model="lifetime" value="1w">1 week
      </label>
    </div>
  </div>
  <button type="button" class="btn btn-primary btn-lg btn-block" @click="save">
  Encrypt Message
  </button>
</form>
</div>
    `,
    data() {
        return {
            secret: '',
            lifetime: '1h',
            options: false,
            error: false,
            short_url: null,
            decryption_key: null
        };
    },
    methods: {
        async save() {
            if (!this.secret) {
                this.error = 'Please enter a secret';
                return;
            }

            // Enforce maximum plaintext length before encryption
            if (this.secret.length > 10000) {
                this.error = 'Secret is too long (max 10,000 characters)';
                return;
            }

            try {
                const { cryptoKey, keyString } = await Crypto.generateKey();
                const encrypted = await Crypto.encrypt(cryptoKey, this.secret);

                const response = await fetch('/v1/secret', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        secret: encrypted,
                        lifetime: this.lifetime || '1h'
                    })
                });

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.message || 'Failed to store secret');
                }

                const data = await response.json();

                // Validate that the returned key is alphanumeric to prevent injection
                const serverKey = data.key;
                if (!/^[A-Za-z0-9]+$/.test(serverKey)) {
                    throw new Error('Invalid key received from server');
                }

                const baseUrl = window.location.protocol + '//' + window.location.host + '/#/s/';
                this.error = false;
                this.secret = '';
                this.short_url = baseUrl + encodeURIComponent(serverKey);
                this.decryption_key = keyString;
            } catch (err) {
                this.error = err.message || 'Failed to store secret';
            }
        }
    }
};

const DisplaySecret = {
    template: `
<div class="alert alert-danger" v-if="invalidPassword">
Invalid Decryption Key
</div>
<div v-if="errorMessage">
  <h3>Secret does not exist</h3>
  <p>It might be caused by <b>any</b> of these reasons</p>
  <h5><span class="glyphicon glyphicon-eye-open" aria-hidden="true"></span> Opened Before</h5>
  <p>A secret can only be displayed ONCE. It might be lost due to a non-techy sender that clicked the URL before sending it to you. The secret might have been compromised and read by someone else. You should contact the sender and request a new secret</p>
  <h5><span class="glyphicon glyphicon-link" aria-hidden="true"></span> Incorrect URL</h5>
  <p>The URL you've been given might be missing some magic digits</p>
  <h5><span class="glyphicon glyphicon-time" aria-hidden="true"></span> Expired Secret</h5>
  <p>No secrets last forever. All secrets expires and self destruct automatically. Lifetime varies from one hour up to one week</p>
  <h5><span class="glyphicon glyphicon-off" aria-hidden="true"></span> Service Restart</h5>
  <p>No secrets are stored on disk, which means that all secrets will be lost if the database backend(memcached) is restarted</p>
  <h5><span class="glyphicon glyphicon-lock" aria-hidden="true"></span> End-to-End Encrypted</h5>
  <p>Secrets are encrypted in your browser before being sent. The server never sees your plaintext data</p>
</div>

<div v-if="secret">
<pre>{{ secret }}</pre>
This secret will not be viewable again, save it!
</div>

<div v-show="display_form">
  <div class="jumbotron">
  <form @submit.prevent="view" v-if="!secret">
    A decryption key is required to view this secret, please enter it below
    <div class="form-group">
      <label>Decryption Key</label>
      <input class="form-control" v-model="form_decryption_key">
    </div>
    <button type="submit" class="btn btn-primary">Decrypt Message</button>
  </form>
  </div>
</div>
    `,
    data() {
        return {
            invalidPassword: false,
            errorMessage: false,
            secret: null,
            display_form: false,
            form_decryption_key: ''
        };
    },
    created() {
        const key = this.$route.params.key;
        const decryptionKey = this.$route.params.decryption_key;

        if (decryptionKey) {
            this.getSecret(key, decryptionKey);
        } else {
            this.display_form = true;
        }
    },
    methods: {
        view() {
            const key = this.$route.params.key;
            this.getSecret(key, this.form_decryption_key);
        },
        async getSecret(key, decryptionKey) {
            const keyPattern = /^[A-Za-z0-9]+$/;

            if (!keyPattern.test(key)) {
                this.errorMessage = true;
                return;
            }

            try {
                const response = await fetch('/v1/secret/' + encodeURIComponent(key));

                if (response.status === 404) {
                    this.errorMessage = true;
                    this.display_form = false;
                    return;
                }

                if (!response.ok) {
                    this.errorMessage = true;
                    return;
                }

                const data = await response.json();
                const plaintext = await Crypto.decrypt(decryptionKey, data.secret);
                this.errorMessage = false;
                this.invalidPassword = false;
                this.secret = plaintext;
            } catch (err) {
                // Decryption failure — report to server for audit logging
                this.invalidPassword = true;
                this.secret = null;
                // Fire-and-forget decryption failure report
                try {
                    fetch('/v1/secret/decryption-failure', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ key: key })
                    });
                } catch (reportErr) {
                    // Best-effort reporting; ignore if it fails
                }
            }
        }
    }
};

// --- Vue Router ---

const routes = [
    { path: '/s/:key/:decryption_key', component: DisplaySecret },
    { path: '/s/:key', component: DisplaySecret },
    { path: '/create', component: CreateSecret },
    { path: '/', redirect: '/create' },
    { path: '/:pathMatch(.*)*', redirect: '/create' }
];

const router = VueRouter.createRouter({
    history: VueRouter.createWebHashHistory(),
    routes
});

// --- Vue App ---

const vueApp = Vue.createApp({
    template: '<router-view></router-view>'
});
vueApp.use(router);
vueApp.mount('#app');

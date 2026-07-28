'use strict';

const app = angular.module('yopass', ['ngRoute']);

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

app.controller('createController', function($scope, $http) {
    // Explicitly initialize view state to prevent flash of error div
    $scope.error = false;

    $scope.toggleoptions = function() {
        $scope.options = true;
    };

    $scope.save = async function(s) {
        if (!s?.secret) {
            $scope.error = 'Please enter a secret';
            return;
        }

        // Enforce maximum plaintext length before encryption
        if (s.secret.length > 10000) {
            $scope.error = 'Secret is too long (max 10,000 characters)';
            return;
        }

        try {
            const { cryptoKey, keyString } = await Crypto.generateKey();
            const encrypted = await Crypto.encrypt(cryptoKey, s.secret);

            const response = await $http.post('/v1/secret', {
                secret: encrypted,
                lifetime: s.lifetime || '1h'
            });

            // Validate that the returned key is alphanumeric to prevent injection
            const serverKey = response.data.key;
            if (!/^[A-Za-z0-9]+$/.test(serverKey)) {
                throw new Error('Invalid key received from server');
            }

            const baseUrl = window.location.protocol + '//' + window.location.host + '/#/s/';
            $scope.error = false;
            $scope.secret = null;
            $scope.short_url = baseUrl + encodeURIComponent(serverKey);
            $scope.decryption_key = keyString;
        } catch (err) {
            $scope.error = (err.data?.message) || err.message || 'Failed to store secret';
        }

        $scope.$applyAsync();
    };
});

app.controller('ViewController', function($scope, $routeParams, $http) {
    // Validate route parameters to prevent injection
    const keyPattern = /^[A-Za-z0-9]+$/;

    // Explicitly initialize view state to prevent flash of error messages
    $scope.invalidPassword = false;
    $scope.errorMessage = false;
    $scope.secret = null;

    async function getSecret(key, decryptionKey) {
        if (!keyPattern.test(key)) {
            $scope.errorMessage = true;
            $scope.$applyAsync();
            return;
        }

        try {
            const response = await $http.get('/v1/secret/' + encodeURIComponent(key));
            const plaintext = await Crypto.decrypt(decryptionKey, response.data.secret);
            $scope.errorMessage = false;
            $scope.invalidPassword = false;
            $scope.secret = plaintext;
        } catch (err) {
            if (err?.status === 404) {
                $scope.errorMessage = true;
                $scope.display_form = false;
            } else if (err?.status) {
                $scope.errorMessage = true;
            } else {
                // Decryption failure — report to server for audit logging
                $scope.invalidPassword = true;
                $scope.secret = null;
                // Use native fetch (fire-and-forget) instead of $http to avoid
                // AngularJS digest-cycle issues when called from a native Promise rejection.
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
        $scope.$applyAsync();
    }

    if ($routeParams.decryption_key) {
        getSecret($routeParams.key, $routeParams.decryption_key);
    } else {
        $scope.display_form = true;
        $scope.view = function(form) {
            getSecret($routeParams.key, form.decryption_key);
        };
    }
});

app.config(function($routeProvider) {
    $routeProvider
        .when('/s/:key/:decryption_key', {
            templateUrl: 'display-secret.html',
            controller: 'ViewController'
        })
        .when('/s/:key', {
            templateUrl: 'display-secret.html',
            controller: 'ViewController'
        })
        .when('/create', {
            templateUrl: 'create-secret.html',
            controller: 'createController'
        })
        .otherwise({
            redirectTo: '/create'
        });
});
'use strict';

let app = angular.module('yopass', ['ngRoute']);

/**
 * Client-side encryption using Web Crypto API (AES-GCM 256-bit).
 * The server never sees the plaintext or the encryption key.
 */
let Crypto = {
    /**
     * Generates a random encryption key and returns it as a URL-safe base64 string.
     */
    generateKey: async function() {
        let key = await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        let exported = await window.crypto.subtle.exportKey('raw', key);
        return { cryptoKey: key, keyString: Crypto._arrayBufferToBase64Url(exported) };
    },

    /**
     * Encrypts plaintext with the given CryptoKey. Returns base64url(iv + ciphertext).
     */
    encrypt: async function(cryptoKey, plaintext) {
        let iv = window.crypto.getRandomValues(new Uint8Array(12));
        let encoded = new TextEncoder().encode(plaintext);
        let ciphertext = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            encoded
        );
        // Prepend IV to ciphertext
        let combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);
        return Crypto._arrayBufferToBase64Url(combined.buffer);
    },

    /**
     * Decrypts ciphertext (base64url encoded with prepended IV) using the given key string.
     */
    decrypt: async function(keyString, ciphertextB64) {
        let rawKey = Crypto._base64UrlToArrayBuffer(keyString);
        let cryptoKey = await window.crypto.subtle.importKey(
            'raw', rawKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );
        let combined = new Uint8Array(Crypto._base64UrlToArrayBuffer(ciphertextB64));
        let iv = combined.slice(0, 12);
        let ciphertext = combined.slice(12);
        let decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            ciphertext
        );
        return new TextDecoder().decode(decrypted);
    },

    _arrayBufferToBase64Url: function(buffer) {
        let bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },

    _base64UrlToArrayBuffer: function(base64url) {
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4 !== 0) { base64 += '='; }
        let binary = atob(base64);
        let buffer = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            buffer[i] = binary.charCodeAt(i);
        }
        return buffer.buffer;
    }
};

app.controller('createController', function($scope, $http) {
    $scope.toggleoptions = function() {
        $scope.options = true;
    };

    $scope.save = function(s) {
        if (!s || !s.secret) {
            $scope.error = 'Please enter a secret';
            return;
        }

        Crypto.generateKey().then(function(keyData) {
            return Crypto.encrypt(keyData.cryptoKey, s.secret).then(function(encrypted) {
                return { keyString: keyData.keyString, encrypted: encrypted };
            });
        }).then(function(result) {
            $http.post('/v1/secret', { secret: result.encrypted, lifetime: s.lifetime || '1h' })
                .then(function(response) {
                    let data = response.data;
                    $scope.error = false;
                    let base_url = window.location.protocol + '//' + window.location.host + '/#/s/';
                    $scope.secret = null;
                    $scope.short_url = base_url + data.key;
                    $scope.decryption_key = result.keyString;
                }, function(response) {
                    $scope.error = response.data ? response.data.message : 'Failed to store secret';
                });
        }).catch(function(err) {
            $scope.$apply(function() {
                $scope.error = 'Encryption failed: ' + err.message;
            });
        });
    };
});

app.controller('ViewController', function($scope, $routeParams, $http) {
    function getSecret(key, decryptionKey) {
        $http.get('/v1/secret/' + key)
            .then(function(response) {
                let data = response.data;
                // Decrypt client-side
                Crypto.decrypt(decryptionKey, data.secret).then(function(plaintext) {
                    $scope.$apply(function() {
                        $scope.errorMessage = false;
                        $scope.invalidPassword = false;
                        $scope.secret = plaintext;
                    });
                }).catch(function() {
                    $scope.$apply(function() {
                        $scope.invalidPassword = true;
                        $scope.secret = null;
                    });
                });
            }, function(response) {
                if (response.status === 404) {
                    $scope.errorMessage = true;
                    $scope.display_form = false;
                } else {
                    $scope.errorMessage = true;
                }
            });
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
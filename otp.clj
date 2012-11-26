;; Copyright (c) 2012, Sölvi Páll Ásgeirsson
;; All rights reserved.
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met: 
;;
;; 1. Redistributions of source code must retain the above copyright notice, this
;;    list of conditions and the following disclaimer. 
;; 2. Redistributions in binary form must reproduce the above copyright notice,
;;    this list of conditions and the following disclaimer in the documentation
;;    and/or other materials provided with the distribution. 
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
;; ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
;; ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;; (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
;; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
;; ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

(ns is.bitbucket.otp
  (:import [org.apache.commons.codec.binary Base32]))

(defn base32-decode [string]
  (.decode (Base32.) string))

(defn base32-encode [string]
  (.encodeToString (Base32.) string))

(defn integer-to-bytebuffer [int]
  (let [buffer (java.nio.ByteBuffer/allocate 8)]
    (.array (.putLong buffer int))))

(defn generate-secret-key
  "Generate a base32-encoded random key"
  []
  (let [bytes (make-array Byte/TYPE 10)]
    (.nextBytes (java.security.SecureRandom.) bytes)
    (base32-encode bytes)))


(defn generate-hmac 
  "Generate a SHA1 HMAC of msg with key, returning a byte array."
  [key msg]
  (let [key (javax.crypto.spec.SecretKeySpec. key "HmacSHA1")
        mac (doto (javax.crypto.Mac/getInstance "HmacSHA1")
              (.init key))]
    (into [] (.doFinal mac msg))))

(defn compute-hotp-value
  "http://tools.ietf.org/html/rfc4226#section-5.4"
  [hash]
  (let [offset (bit-and (hash 19) 0xf)
        binary (bit-or (bit-shift-left (bit-and (hash offset) 0x7f) 24)
                       (bit-shift-left (bit-and (hash (+ offset 1)) 0xff) 16)
                       (bit-shift-left (bit-and (hash (+ offset 2)) 0xff) 8)
                       (bit-and (hash (+ offset 3)) 0xff))]
    (mod binary 1000000)))

(defn generate-hotp 
  "Generate a counter-based HMAC-OTP"
  [secret interval]
  (let [key (base32-decode secret)
        hash (generate-hmac key (integer-to-bytebuffer interval))]
    (format "%06d" (compute-hotp-value hash))))


(defn generate-totp 
  "Generate a time-based HMAC-OTP
If time-offset is provided, offset the current system time with time-offset seconds"
  ([secret] (generate-totp secret 0))
  ([secret time-offset]
     (generate-hotp secret (/ (+ (/ (System/currentTimeMillis) 1000) 
                                 time-offset) 
                              30))))

(defn verify-totp
  "Verify a time-based OTP.  
Return true if token is valid according to secret, nil otherwise.
If token-offset is provided, verify against token-offset many values in the future and in the past, i.e., if token-offset is 1, verify against last, current and next token."
  ([secret token] (verify-totp secret token 0))
  ([secret token token-offset]
     (let [offsets (range (* 30 token-offset -1) (+ 1 (* 30 token-offset)) 30)]
       (some (fn [offset-token]
               (= offset-token token))
             (map (fn [time-offset]
                    (generate-totp secret time-offset))
                  offsets)))))


package org.foxden.jwt

// Install Nimbus JOSE+JWT
@Grab(group='com.nimbusds', module='nimbus-jose-jwt', version='[9.9.3,)')
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.RSASSASigner

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT

import groovy.json.JsonSlurper
import java.time.Duration

// OPTIONAL: JWK.parseFromPEMEncodedObjects() depends on bouncycastle
// at runtime to convert Google's PEM-encoded private key to the RSAPrivateKey
// format required by `new RSASSASigner(privateKey)`.
//
// This could be skipped for Hubitat -- users might be able to convert the
// PEM-encoded key to JSON manually and use com.nimbudsds.jose.jwk.RSAKey.parse()
@Grab(group='org.bouncycastle', module='bcpkix-jdk15on', version='[1.68,)')
import com.nimbusds.jose.jwk.JWK

if (args.size() < 1) {
    // Key in JSON format from Google Service Account, see instructions at:
    //
    // https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount
    println("Missing argument: path/to/key.json")
    System.exit(1)
}

def jsonSlurper = new JsonSlurper()
def keyJson = jsonSlurper.parse(new File(args[0]))

def header = new JWSHeader.Builder(JWSAlgorithm.RS256)
    .keyID(keyJson.private_key_id)
    .type(JOSEObjectType.JWT)
    .build()

def issueTime = new Date()
def expireTime = issueTime.toInstant().plus(Duration.ofHours(24)).toDate()
def payload = new JWTClaimsSet.Builder()
    .audience(keyJson.project_id)
    .issueTime(issueTime)
    .expirationTime(expireTime)
    .build()

def signedJWT = new SignedJWT(header, payload)
def jwk = JWK.parseFromPEMEncodedObjects(keyJson.private_key)
def signer = new RSASSASigner(jwk.toRSAPrivateKey())
signedJWT.sign(signer)

println(signedJWT.serialize())

# SlhDsaSha2_256s Class
 

Implements the SLH-DSA-SHA2-256s signature scheme.


## Inheritance Hierarchy
<a href="https://docs.microsoft.com/dotnet/api/system.object" target="_blank" rel="noopener noreferrer">System.Object</a><br />&nbsp;&nbsp;<a href="d86dc076-6326-0697-9d41-f18e749ac510">PQnet.SlhDsaBase</a><br />&nbsp;&nbsp;&nbsp;&nbsp;PQnet.SlhDsaSha2_256s<br />
**Namespace:**&nbsp;<a href="fc4f881f-e121-9cf0-ed49-65bf6b5a005d">PQnet</a><br />**Assembly:**&nbsp;PQnet (in PQnet.dll) Version: 1.0.0+63cbb78a507491a71ebd4891944ebbfe930c1a59

## Syntax

**C#**<br />
``` C#
public class SlhDsaSha2_256s : SlhDsaBase
```

**VB**<br />
``` VB
Public Class SlhDsaSha2_256s
	Inherits SlhDsaBase
```

<br />
The SlhDsaSha2_256s type exposes the following members.


## Constructors
&nbsp;<table><tr><th></th><th>Name</th><th>Description</th></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="8551c66f-7c31-e1c4-de24-2d0bcd5ef2fc">SlhDsaSha2_256s()</a></td><td>
Instantiates a new SlhDsaSha2_256s object with non-deterministic signatures.</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="c95a15ab-a1dd-7d04-a1d7-39061216c4d4">SlhDsaSha2_256s(Boolean)</a></td><td>
Instantiates a new SlhDsaSha2_256s object.</td></tr></table>&nbsp;
<a href="#slhdsasha2_256s-class">Back to Top</a>

## Properties
&nbsp;<table><tr><th></th><th>Name</th><th>Description</th></tr><tr><td>![Public property](media/pubproperty.gif "Public property")</td><td><a href="f865fc26-0bab-b2db-cab4-2266b5be6acd">Deterministic</a></td><td>
Gets or sets whether signature generation is deterministic
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public property](media/pubproperty.gif "Public property")</td><td><a href="8cddb8c2-1a54-7e14-6112-ac50cad9cf9e">Name</a></td><td>
Gets the name of the algorithm
 (Overrides <a href="081c55a6-16cf-3ce7-22c3-aeac56ad39a2">SlhDsaBase.Name</a>.)</td></tr><tr><td>![Public property](media/pubproperty.gif "Public property")</td><td><a href="387b4d4b-43e7-56f5-6ae6-86da617354ba">NistSecurityCategory</a></td><td>
Gets the NIST security category of the cryptographic algorithm.
 (Overrides <a href="d91593fe-879c-503c-c94d-0ca3be588f81">SlhDsaBase.NistSecurityCategory</a>.)</td></tr><tr><td>![Public property](media/pubproperty.gif "Public property")</td><td><a href="8fbff1c2-9682-4d3d-2cbb-7d71b2ad6631">PrivateKeyBytes</a></td><td>
Gets the size, in bytes, of the private key
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public property](media/pubproperty.gif "Public property")</td><td><a href="e81601b4-ca49-7135-77d5-164e8b6f6f15">PublicKeyBytes</a></td><td>
Gets the size, in bytes, of the public key
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public property](media/pubproperty.gif "Public property")</td><td><a href="bc2935a2-953c-3eae-2fab-a8205cb709a3">SeedBytes</a></td><td>
Gets the size, in bytes, of the seed used for key generation
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public property](media/pubproperty.gif "Public property")</td><td><a href="0204d1a9-3363-df39-6059-8de7f71f5b70">SignatureBytes</a></td><td>
Gets the size, in bytes, of the signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr></table>&nbsp;
<a href="#slhdsasha2_256s-class">Back to Top</a>

## Methods
&nbsp;<table><tr><th></th><th>Name</th><th>Description</th></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="https://docs.microsoft.com/dotnet/api/system.object.equals#system-object-equals(system-object)" target="_blank" rel="noopener noreferrer">Equals</a></td><td>
Determines whether the specified object is equal to the current object.
 (Inherited from <a href="https://docs.microsoft.com/dotnet/api/system.object" target="_blank" rel="noopener noreferrer">Object</a>.)</td></tr><tr><td>![Protected method](media/protmethod.gif "Protected method")</td><td><a href="https://docs.microsoft.com/dotnet/api/system.object.finalize#system-object-finalize" target="_blank" rel="noopener noreferrer">Finalize</a></td><td>
Allows an object to try to free resources and perform other cleanup operations before it is reclaimed by garbage collection.
 (Inherited from <a href="https://docs.microsoft.com/dotnet/api/system.object" target="_blank" rel="noopener noreferrer">Object</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="1a0e5397-be4b-8269-dd31-599e05001698">GenerateKeyPair(Byte[], Byte[])</a></td><td>
Generates a SLH-DSA key pair. Throws if an error occurs
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="0d4ed9c3-2760-0f13-d71e-ab072add4b78">GenerateKeyPair(Byte[], Byte[], String)</a></td><td>
Generates a SLH-DSA key pair.
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="6da10beb-0b27-7396-02a3-90a56eced7ab">GenerateKeyPair(Byte[], Byte[], Byte[], String)</a></td><td>
Generates a SLH-DSA key pair.
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="https://docs.microsoft.com/dotnet/api/system.object.gethashcode#system-object-gethashcode" target="_blank" rel="noopener noreferrer">GetHashCode</a></td><td>
Serves as the default hash function.
 (Inherited from <a href="https://docs.microsoft.com/dotnet/api/system.object" target="_blank" rel="noopener noreferrer">Object</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="https://docs.microsoft.com/dotnet/api/system.object.gettype#system-object-gettype" target="_blank" rel="noopener noreferrer">GetType</a></td><td>
Gets the <a href="https://docs.microsoft.com/dotnet/api/system.type" target="_blank" rel="noopener noreferrer">Type</a> of the current instance.
 (Inherited from <a href="https://docs.microsoft.com/dotnet/api/system.object" target="_blank" rel="noopener noreferrer">Object</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="7792ec2e-d42b-0e51-40ba-2080db18bcbe">hash_slh_sign</a></td><td>
FIPS 205 Algorithm 23 - Generates a pre-hash SLH-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="20d5945e-33a5-a362-6d3d-5e64c4361895">hash_slh_verify</a></td><td>
FIPS 205 Algorithm 25 - Verifies a pre-hash SLH-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Protected method](media/protmethod.gif "Protected method")</td><td><a href="https://docs.microsoft.com/dotnet/api/system.object.memberwiseclone#system-object-memberwiseclone" target="_blank" rel="noopener noreferrer">MemberwiseClone</a></td><td>
Creates a shallow copy of the current <a href="https://docs.microsoft.com/dotnet/api/system.object" target="_blank" rel="noopener noreferrer">Object</a>.
 (Inherited from <a href="https://docs.microsoft.com/dotnet/api/system.object" target="_blank" rel="noopener noreferrer">Object</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="9e7fe6e4-2601-874e-f658-9bcc188b8b04">Sign(Byte[], Byte[], Byte[])</a></td><td>
Generate a pure ML-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="4e26e274-c360-e2c7-ad93-7d3e9d6482e9">Sign(Byte[], Byte[], Byte[], Byte[])</a></td><td>
Generate a pure ML-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="6a46f20f-31fb-6e28-e693-dd4cbd637a98">Sign(Byte[], Byte[], Byte[], Byte[], String)</a></td><td>
Generate a pure ML-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="c3e5c277-6965-b9ee-d2b5-3ee59b94ef7b">SignHash(Byte[], Byte[], PreHashFunction, Byte[])</a></td><td>
Generate a ML-DSA signature for a digest ("pre-hash signature")
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="8cdc2547-e105-7977-b50e-2ab91edc379a">SignHash(Byte[], Byte[], Byte[], PreHashFunction, Byte[])</a></td><td>
Generate a ML-DSA signature for a digest ("pre-hash signature")
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="344dab00-f54f-d330-bc75-0e6e9ecef694">SignHash(Byte[], Byte[], Byte[], PreHashFunction, Byte[], String)</a></td><td>
Generate a ML-DSA signature for a digest ("pre-hash signature")
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="246c7cd7-289d-8393-4529-38e47353ee84">slh_keygen</a></td><td>
FIPS 205 Algorithm 21 - Generates an SLH-DSA key pair
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="c12c53ba-9cb5-50e2-0d7e-b7b8d072f89e">slh_sign</a></td><td>
FIPS 205 Algorithm 22 - Generates a pure SLH-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="5b3d0522-70f0-88ea-f95d-0116ea2f88df">slh_verify</a></td><td>
FIPS 205 Algorithm 24 - Verifies a pure SLH-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="https://docs.microsoft.com/dotnet/api/system.object.tostring#system-object-tostring" target="_blank" rel="noopener noreferrer">ToString</a></td><td>
Returns a string that represents the current object.
 (Inherited from <a href="https://docs.microsoft.com/dotnet/api/system.object" target="_blank" rel="noopener noreferrer">Object</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="61a88890-d1cd-73b6-be4d-7e68cb61dbc7">Verify(Byte[], Byte[], Byte[])</a></td><td>
Verify a pure ML-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="419dfecc-c21e-9c7f-8416-bf73c058f852">Verify(Byte[], Byte[], Byte[], Byte[])</a></td><td>
Verify a pure ML-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="85bbfbed-a058-7d2f-1822-9e3c4d8b0497">Verify(Byte[], Byte[], Byte[], Byte[], String)</a></td><td>
Verify a pure ML-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="216b0a08-02b5-705e-1f1f-803fa262b9e7">VerifyHash(Byte[], Byte[], PreHashFunction, Byte[])</a></td><td>
Verify a digest ("pre-hash") ML-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="a78e7538-d613-f27d-3e9b-84dc52f000fd">VerifyHash(Byte[], Byte[], Byte[], PreHashFunction, Byte[])</a></td><td>
Verify a digest ("pre-hash") ML-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr><tr><td>![Public method](media/pubmethod.gif "Public method")</td><td><a href="285b6940-bce2-2acb-6ca1-21c4329904eb">VerifyHash(Byte[], Byte[], Byte[], PreHashFunction, Byte[], String)</a></td><td>
Verify a digest ("pre-hash") ML-DSA signature
 (Inherited from <a href="d86dc076-6326-0697-9d41-f18e749ac510">SlhDsaBase</a>.)</td></tr></table>&nbsp;
<a href="#slhdsasha2_256s-class">Back to Top</a>

## See Also


#### Reference
<a href="fc4f881f-e121-9cf0-ed49-65bf6b5a005d">PQnet Namespace</a><br />
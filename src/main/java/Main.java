import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.GetResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

public class Main {
    private static final Path KEY_DIR = Path.of("keys");
    private static final Path PRIVATE_KEY = KEY_DIR.resolve("private.pem");
    private static final Path PUBLIC_KEY = KEY_DIR.resolve("public.pem");

    private static final String QUEUE = "jwt-demo-queue";
    private static final String MESSAGE = "may just go where no one's been";

    private static final String CONFIGURE_PERMISSIONS = "emre_rabbitmq_server.configure:*/*";
    private static final String WRITE_PERMISSIONS = "emre_rabbitmq_server.write:*/*";
    private static final String READ_PERMISSIONS = "emre_rabbitmq_server.read:*/*";

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: generate-keys | test | test-write-only");
            return;
        }

        switch (args[0]) {
            case "generate-keys" -> generateKeys();
            case "test" -> testRabbitMq();
            case "test-write-only" -> testWriteOnly();
            default -> System.out.println("Unknown command: " + args[0]);
        }
    }

    // if the keys do not present, this generates keys.
    private static void generateKeys() throws Exception {
        if (Files.exists(PRIVATE_KEY) || Files.exists(PUBLIC_KEY)) {
            throw new IllegalStateException("Keys already exist. Delete both keys to regenerate them.");
        }

        Files.createDirectories(KEY_DIR);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();

        savePem(
                PRIVATE_KEY,
                "PRIVATE KEY",
                keyPair.getPrivate().getEncoded()
        );

        savePem(
                PUBLIC_KEY,
                "PUBLIC KEY",
                keyPair.getPublic().getEncoded()
        );

        System.out.println("RSA keys generated successfully.");
    }

    // converts a cryptographic key into PEM format and saves it to a file
    private static void savePem(Path path, String type, byte[] encoded) throws Exception {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);

        String pem = "-----BEGIN " + type + "-----\n"
                + base64
                + "\n-----END " + type + "-----\n";

        Files.writeString(path, pem, StandardCharsets.US_ASCII);
    }

    // generates the jwt, trust me
    private static String generateJwt(String scope) throws Exception {
        String pem = Files.readString(PRIVATE_KEY);

        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(base64);

        //The RSA key generation uses the standard Java Cryptography Architecture, so you don't need OpenSSL
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(decoded)
        );

        Instant now = Instant.now();

        //The JWT generation uses Nimbus to create a token containing these claims:
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("java-test-service")
                .audience("emre_rabbitmq_server")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(3600)))
                .claim("scope", scope)
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID("local-key")
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(privateKey));

        return jwt.serialize();
    }


    //tests the rabbitmq connection&authentication
    private static void testRabbitMq() throws Exception {
        //all permissions
        String jwt = generateJwt(
                CONFIGURE_PERMISSIONS + " " +
                        WRITE_PERMISSIONS + " " +
                        READ_PERMISSIONS
        );

        ConnectionFactory factory = createConnectionFactory(jwt);
        try (
                Connection connection = factory.newConnection();
                Channel channel = connection.createChannel()
        ) {
            System.out.println("JWT authentication successful!");
            tryCreateQueue(channel);
            tryWriteQueue(channel, MESSAGE);
            tryReadQueue(channel);
        }
        catch (Exception e) {
            System.out.println("connection failed: " + e.getMessage());
        }
    }

    private static void testWriteOnly() throws Exception {
        String writePermissionJwt = generateJwt(WRITE_PERMISSIONS);

        ConnectionFactory factory1 = createConnectionFactory(writePermissionJwt);
        try (
                Connection connection = factory1.newConnection();
                Channel channel = connection.createChannel()
        ) {
                tryWriteQueue(channel, MESSAGE);
                tryReadQueue(channel);
        } catch (Exception e) {
            System.out.println("try-with-resources block tried to close an already killed channel");
        }

        String allPermissions = CONFIGURE_PERMISSIONS + " " +
                WRITE_PERMISSIONS + " " +
                READ_PERMISSIONS;
        String allPermissionsJwt = generateJwt(allPermissions);

        ConnectionFactory factory2 = createConnectionFactory(allPermissionsJwt);
        try (
                Connection connection = factory2.newConnection();
                Channel channel = connection.createChannel()
        ) {
                tryReadQueue(channel);
        }
    }

    private static ConnectionFactory createConnectionFactory(String scope) {
        ConnectionFactory connectionFactory = new ConnectionFactory();
        connectionFactory.setHost("localhost");
        connectionFactory.setPort(5672);
        connectionFactory.setVirtualHost("/");

        //RabbitMQ OAuth backend expects the JWT as password.
        // the username is ignored as follows
        connectionFactory.setUsername("ignored");
        connectionFactory.setPassword(scope);
        return connectionFactory;
    }

    private static void tryCreateQueue(Channel channel) {
        try {
            channel.queueDeclare(
                    QUEUE,
                    false,
                    false,
                    false,
                    null
            );
        }
        catch (IOException e) {
            System.out.println("authz error: configure operation denied");
        }
    }

    private static void tryWriteQueue(Channel channel, String message) {
        try {
            channel.basicPublish(
                    "",
                    QUEUE,
                    null,
                    message.getBytes(StandardCharsets.UTF_8)
            );
        }
        catch (IOException e) {
            System.out.println("authz error: write operation denied");
        }
    }

    private static void tryReadQueue(Channel channel) {
        try {
            GetResponse response = channel.basicGet(QUEUE, true);

            if (response != null) {
                //String received = new String(response.getBody(), StandardCharsets.UTF_8);
                String received = new String(response.getBody());

                System.out.println("message received: " + received);
            }
            else {
                System.out.println("queue is empty");
            }
        }
        catch (IOException e) {
            System.out.println("authz error: read operation denied");
        }
    }
}

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

public class Main {

    private static String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "x", bi);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static byte[] getClientProof(String clientNone, String serverNonce, String password, String salt, int iterations)
    {
        String msg = clientNone + "," + serverNonce + "," + serverNonce;

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec0 = new PBEKeySpec(password.toCharArray(), hexStringToByteArray(salt), iterations, 64*4);
            SecretKey spec1 = factory.generateSecret(spec0);

            Mac hasher = Mac.getInstance("HmacSHA256");
            hasher.init(new SecretKeySpec("Client Key".getBytes("utf-8"), "HmacSHA256"));

            byte[] hash = hasher.doFinal(spec1.getEncoded());

            // stored key now
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(hash);

            // signature
            Mac signature = Mac.getInstance("HmacSHA256");
            signature.init(new SecretKeySpec(msg.getBytes("utf-8"), "HmacSHA256"));
            byte[] signatureBytes = signature.doFinal(encodedHash);

            byte[] clientProof =  new byte[hash.length];
            int i = 0;
            while ( i < hash.length) {
                int val = hash[i] ^ signatureBytes[i];
                clientProof[i] = (byte)val;
                i = i + 1;
            }
            return clientProof;
        }
        catch(Exception e) {
            System.out.println(e);
        }

        return null;

        }

    private static float bytesToGigabytes(float bytes) {
        return bytes*(1e-9f);
    }

    public static void main(String [] args) {

        String MODEM_IP = "192.168.8.1";
        String HOMEPAGE = "http://" + MODEM_IP + "/html/home.html";
        String LOGIN = "http://" + MODEM_IP + "/api/user/login";
        String TRAFFIC_STATS_URL = "http://" + MODEM_IP + "/api/monitoring/traffic-statistics";
        String AUTHENTICATION_LOGIN = "http://"+ MODEM_IP + "/api/user/authentication_login";
        String SIGNAL_URL = "http://" + MODEM_IP + "/api/device/signal";

        // common header used throughout SCRAM process
        String REQUEST_TOKEN = "__RequestVerificationToken";

        String ADMIN_PASSWORD = "password";

        try {

            // traffic stats
            Document trafficDocument = Jsoup.connect(TRAFFIC_STATS_URL).get();
            int currentConnectionTime = Integer.parseInt(trafficDocument.selectFirst("currentconnecttime").text());

            Float currentUpload = Float.parseFloat(trafficDocument.selectFirst("currentupload").text());
            Float currentDownload = Float.parseFloat(trafficDocument.selectFirst("currentdownload").text());
            Float currentDownloadRate = Float.parseFloat(trafficDocument.selectFirst("currentdownloadrate").text());
            Float currentUploadRate = Float.parseFloat(trafficDocument.selectFirst("currentuploadrate").text());

            Float totalUpload = Float.parseFloat(trafficDocument.selectFirst("totalupload").text());
            Float totalDownload = Float.parseFloat(trafficDocument.selectFirst("totaldownload").text());
            int  totalConnectTime = Integer.parseInt(trafficDocument.selectFirst("totalconnecttime").text());


            // make a request to homepage so that we can get a reference to SessionID cookie
            Connection.Response res = Jsoup.connect(HOMEPAGE).execute();
            Document doc = res.parse();
            String sessionID = res.cookie("SessionID");

            // Begin SCRAM authentication
            String clientNonce = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");

            // B525 uses last 32 bits of server token
            String serverToken = Jsoup.connect("http://192.168.8.1/api/webserver/token").get().selectFirst("token").text();
            serverToken = serverToken.substring(serverToken.length() - 32, serverToken.length());

            String scramBodyRequest = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><username>admin</username><firstnonce>" + clientNonce + "</firstnonce><mode>1</mode></request>";
            res = Jsoup.connect("http://192.168.8.1/api/user/challenge_login").requestBody(scramBodyRequest).header("Content-type", "text/html").header(REQUEST_TOKEN, serverToken).cookie("SessionID", sessionID).method(Connection.Method.POST).execute();

            String verificationToken = res.header(REQUEST_TOKEN);
            Document authDocument = res.parse();
            String serverNonce = authDocument.selectFirst("servernonce").text();
            String salt = authDocument.selectFirst("salt").text();
            int iterations = Integer.parseInt(authDocument.selectFirst("iterations").text());

            byte [] proof = getClientProof(clientNonce, serverNonce, ADMIN_PASSWORD, salt, iterations);

            String loginBody = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><clientproof>"+toHex(proof)+"</clientproof><finalnonce>"+serverNonce+"</finalnonce></request>";
            res = Jsoup.connect(AUTHENTICATION_LOGIN).requestBody(loginBody).header("Content-type", "application/x-www-form-urlencoded; charset=UTF-8").header(REQUEST_TOKEN, verificationToken).cookie("SessionID", sessionID).method(Connection.Method.POST).execute();

            String loggedInCookie = res.cookie("SessionID");

            res = Jsoup.connect(SIGNAL_URL).cookie("SessionID", loggedInCookie).execute();

            // stats related to signal device information
            Document signalDocument = res.parse();

            int cellID = Integer.parseInt(signalDocument.selectFirst("cell_id").text());
            int rsrq = Integer.parseInt(signalDocument.selectFirst("rsrq").text().replace("dB", ""));
            int rsrp = Integer.parseInt(signalDocument.selectFirst("rsrp").text().replace("dBm",""));
            int rssi = Integer.parseInt(signalDocument.selectFirst("rssi").text().replace("dBm", ""));
            int sinr = Integer.parseInt(signalDocument.selectFirst("sinr").text().replace("dB",""));
            int band = Integer.parseInt(signalDocument.selectFirst("band").text());
            int uploadBandwidth = Integer.parseInt(signalDocument.selectFirst("ulbandwidth").text().replace("MHz", ""));
            int downloadBandwidth = Integer.parseInt(signalDocument.selectFirst("dlbandwidth").text().replace("MHz",""));

            //System.out.println(signal_doc.toString());
            System.out.println("cellID: " + cellID);
            System.out.println("rsrq: " + rsrq);
            System.out.println("rsrp: " + rsrp);
            System.out.println("rssi: " + rssi);
            System.out.println("sinr: " + sinr);
            System.out.println("band: " + band);
            System.out.println("ub: " + uploadBandwidth);
            System.out.println("db: " + downloadBandwidth);
        }

        catch(Exception e) {
            System.out.println(e);
        }
    }
}

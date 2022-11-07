package seguridad20222_servidor;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Cliente{

    public static int port=4030;
    public static String host="localhost";
    private BigInteger g;
    private BigInteger p;
    private BigInteger gx;
    private PublicKey publicKeyServer;
    private byte[] firmaServer;
    private static SecurityFunctions f;	
    private String pgx;
    



    public void recibirDatosServer(BufferedReader in, PrintWriter env ) throws Exception {
        env.println("1");
        g = new BigInteger(in.readLine());
        p = new BigInteger(in.readLine());
        gx= new BigInteger(in.readLine());
        pgx = this.g +","+this.p+"," +this.gx;
        //get public key from server
        this.publicKeyServer=f.read_kplus("Caso3/seguridad20222_servidor/datos_asim_srv.pub",in.readLine());


        String firma= in.readLine();
        System.out.println("se recupero Firma: " + firma);
        firmaServer= f.str2byte(firma);

        boolean Vereificacion= f.checkSignature(publicKeyServer, firmaServer, pgx);

        if(Vereificacion) {
            System.out.println("Verificacion exitosa");
            env.println("OK");
            // choose a random bigInteger for diffie hellman
            Random rand = new Random();

            BigInteger x = new BigInteger(128, rand);
            // calculate gy
            BigInteger gy = g.modPow(x, p);
            //send gy to server
            env.println(gy.toString());
            // calculate master key
            BigInteger masterkey=calcular_llave_maestra(gx, x, p);
            System.out.println("Llave maestra: "+masterkey.toString());
            // generating simeetric key
            SecretKey sk_c = f.csk1(masterkey.toString());
            SecretKey sk_mac= f.csk2(masterkey.toString());

            
            //genera consulta int random
            int valorConsulta=  (int) (Math.random() * 1000);
            System.out.println("Valor de la consulta: "+valorConsulta);
            byte[] consultaBytes= Integer.toString(valorConsulta).getBytes(); 
            byte[] iv1 = generateIvBytes();
            String str_iv1 = f.byte2str(iv1);
            IvParameterSpec ivSpec2 = new IvParameterSpec(iv1);
            //encrypt consulta
            byte[] consultaEnc = f.senc(consultaBytes, sk_c, ivSpec2,"Cliente");
            //garantizar integridad
            byte[] consultaMac = f.hmac(consultaBytes, sk_mac);
            //enviar consulta
            env.println(f.byte2str(consultaEnc));
            //ENVIAR MAC
            env.println(f.byte2str(consultaMac));
            //ENVIAR IV
            env.println(str_iv1);



            //send iv1 to server
            env.println(f.byte2str(iv1));

        }else {
            // send error to server
            env.println("ERROR");
            System.out.println("Verificacion fallida");
        }

   
    }

    public static void main(String[] args) throws Exception {

        f = new SecurityFunctions();
        Socket s = new Socket(host, port);
        BufferedReader in = new BufferedReader(new java.io.InputStreamReader(s.getInputStream()));
        PrintWriter env = new PrintWriter(s.getOutputStream(), true);
        Cliente c = new Cliente();
        c.recibirDatosServer(in, env);
        s.close();
    }

  
    

    private BigInteger calcular_llave_maestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
        return base.modPow(exponente, modulo);
}
    private byte[] generateIvBytes() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }


}
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

public class Cliente extends Thread {
    public static int port=4030;
    public static String host="localhost";
    private BigInteger g;
    private BigInteger p;
    private BigInteger gx;
    private PublicKey publicKeyServer;
    private byte[] firmaServer;
    private static SecurityFunctions f;	
    private String pgx;
    private int clientID=0;
    



    public void recibirDatosServer(BufferedReader in, PrintWriter env ) throws Exception {
        //converts clientID to string
        String clientIDString = Integer.toString(clientID);
        env.println(clientIDString);
        g = new BigInteger(in.readLine());
        p = new BigInteger(in.readLine());
        gx= new BigInteger(in.readLine());
        pgx = this.g +","+this.p+"," +this.gx;
        //get public key from server
        this.publicKeyServer=f.read_kplus("Caso3/seguridad20222_servidor/datos_asim_srv.pub",in.readLine());


        String firma= in.readLine();
        firmaServer= f.str2byte(firma);

        boolean Vereificacion= f.checkSignature(publicKeyServer, firmaServer, pgx);

        if(Vereificacion) {
            System.out.println("Verificacion de firma exitosa");
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
            // generating simeetric key
            SecretKey sk_c = f.csk1(masterkey.toString());
            SecretKey sk_mac= f.csk2(masterkey.toString());

            
            //genera consulta int random
            int valorConsulta=  (int) (Math.random() * 1000);
            System.out.println("Valor de consulta: "+valorConsulta);
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


            String linea=in.readLine();
            if(linea.compareTo("OK")==0) {
                System.out.println("Consulta verificada");
                //recibir respuesta
                String respuestaEnc=in.readLine();
                String respuestaMac=in.readLine();
                String respuestaIv=in.readLine();
                IvParameterSpec ivSpec1 = new IvParameterSpec(f.str2byte(respuestaIv));
                //desencriptar respuesta
                byte[] respuestaBytes= f.sdec(f.str2byte(respuestaEnc), sk_c, ivSpec1);
                //verificar integridad
                byte[] respuestaMacBytes= f.str2byte(respuestaMac);
                boolean integridad= f.checkInt(respuestaBytes, sk_mac, respuestaMacBytes);
                if(integridad) {
                    //print respuesta 
                    System.out.println("Respuesta: "+new String(respuestaBytes));
                    System.out.println(" valor Respuesta recibida");
                    env.println("OK");
                    System.out.println("Respuesta: "+ new String(respuestaBytes));
                }else {
                    env.println("ERROR");
                    System.out.println("Respuesta no recibida, integridad comprometida o no verificada"); 
                }
  

        }else {
            // send error to server
            env.println("ERROR");
            System.out.println("Verificacion fallida");
        }}
        else {
            // send error to server
            env.println("ERROR");
            System.out.println("Verificacion fallida, la firma no coincide con los datos");
        }

   
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Digite la cantidad de clientes a crear");
        BufferedReader inC = new BufferedReader(new java.io.InputStreamReader(System.in));
        int cantidad = Integer.parseInt(inC.readLine());
       
        for(int i=0; i<cantidad; i++) {
            Cliente c = new Cliente();
            c.start();
        }

    }

  
    public void run(){
        try {
            f= new SecurityFunctions();
            Socket s = new Socket(host, port);
            BufferedReader in = new BufferedReader(new java.io.InputStreamReader(s.getInputStream()));
            PrintWriter env = new PrintWriter(s.getOutputStream(), true);
            Cliente c = new Cliente();
            c.recibirDatosServer(in, env);
            s.close();
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
    }}
    

    private BigInteger calcular_llave_maestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
        return base.modPow(exponente, modulo);
}
    private byte[] generateIvBytes() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }


}
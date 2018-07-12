package paquete;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;  
import java.util.ArrayList;  
import java.util.Arrays;  
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;  
  
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;  
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class envia {  
    
    private static String asString(final byte[] mac) {
    final StringBuilder buf = new StringBuilder();
    for (byte b : mac) {
      if (buf.length() != 0) {
        buf.append(':');
      }
      if (b >= 0 && b < 16) {
        buf.append('0');
      }
      buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
    }

    return buf.toString();
  }
    
  public static void main(String[] args){//throws FileNotFoundException, IOException{ 
    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
    StringBuilder errbuf = new StringBuilder(); // For any error msgs  
    String ip_interfaz="";
   /***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}

		System.out.println("Dispositivos encontrados:");
		int i = 0;
                try{
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        System.out.printf("\n#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
                        Iterator<PcapAddr> it = device.getAddresses().iterator();
                        while(it.hasNext()){
                            PcapAddr dir = it.next();//dir, familia, mascara,bc
                            PcapSockAddr direccion =dir.getAddr();
                            byte[]d_ip = direccion.getData();
                            int familia=direccion.getFamily();
                            int[]ipv4 = new int[4];
                            if(familia==org.jnetpcap.PcapSockAddr.AF_INET){
                                ipv4[0]=((int)d_ip[0]<0)?((int)d_ip[0])+256:(int)d_ip[0];
                                ipv4[1]=((int)d_ip[1]<0)?((int)d_ip[1])+256:(int)d_ip[1];
                                ipv4[2]=((int)d_ip[2]<0)?((int)d_ip[2])+256:(int)d_ip[2];
                                ipv4[3]=((int)d_ip[3]<0)?((int)d_ip[3])+256:(int)d_ip[3];
                                
                                System.out.println("\nIP4->"+ipv4[0]+"."+ipv4[1]+"."+ipv4[2]+"."+ipv4[3]);
                            }else if(familia==org.jnetpcap.PcapSockAddr.AF_INET6){
                                System.out.print("\nIP6-> ");
                                for(int z=0;z<d_ip.length;z++)
                                    System.out.printf("%02X:",d_ip[z]);
                            }//if
                        }//while
		}//for
                }catch(IOException io){
                  io.printStackTrace();
                }//catch
   try{
       BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
       System.out.println("\nElije la interfaz de red:");
       int interfaz = Integer.parseInt(br.readLine());
    PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device  
       /******************************************************/
        Iterator<PcapAddr> it1 = device.getAddresses().iterator();
        while(it1.hasNext()){
         PcapAddr dir = it1.next();//dir, familia, mascara,bc
         PcapSockAddr direccion1 =dir.getAddr();
         byte[]d_ip = direccion1.getData(); //esta sera la ip origen
         int familia=direccion1.getFamily();
         int[]ipv4_1 = new int[4];
         if(familia==org.jnetpcap.PcapSockAddr.AF_INET){
            ipv4_1[0]=((int)d_ip[0]<0)?((int)d_ip[0])+256:(int)d_ip[0];
            ipv4_1[1]=((int)d_ip[1]<0)?((int)d_ip[1])+256:(int)d_ip[1];
            ipv4_1[2]=((int)d_ip[2]<0)?((int)d_ip[2])+256:(int)d_ip[2];
            ipv4_1[3]=((int)d_ip[3]<0)?((int)d_ip[3])+256:(int)d_ip[3];
            ip_interfaz = ipv4_1[0]+"."+ipv4_1[1]+"."+ipv4_1[2]+"."+ipv4_1[3];  
            System.out.println("\nInterfaz que se usara:"+ip_interfaz);
        }
        }
       /******************************************************/
       System.out.print("MAC ORIGEN: ");   
       byte[] MACo = device.getHardwareAddress();
       for(int j=0;j<MACo.length;j++)
    System.out.printf("%02X ",MACo[j]); 
        
    /***************************************** 
     * Second we open a network interface 
     *****************************************/  
    int snaplen = 64 * 1024; // Capture all packets, no trucation  
    int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
    int timeout = 10 * 1000; // 10 seconds in millis  
    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
  
  
    /******************************************************* 
     * Third we create our crude packet we will transmit out 
     * This creates a broadcast packet 
     *******************************************************/  
    //tamaño de la trama
    byte[] trama = new byte[1040];
   //Mac origen
    for(int k=0;k<MACo.length;k++){
        trama[k] = (byte) 0xff;
        trama[k+6]=MACo[k];
    }//for
	
//NetworkInterface n = NetworkInterface.getByIndex(3);
////NetworkInterface n = NetworkInterface.getByName("eth3");
//System.out.println("iiiiiii: "+device.getDescription());
//NetworkInterface n = NetworkInterface.getByName(device.getDescription());        
//Enumeration ee = n.getInetAddresses();
//InetAddress IPorigen=InetAddress.getByName(ip_interfaz);
//    while (ee.hasMoreElements())
//    {
//        InetAddress ii = (InetAddress) ee.nextElement();
//        System.out.println("IP: "+ii.getHostAddress());
//        if(ii instanceof java.net.Inet4Address)
//            IPorigen = ii;
//    }
//    /////////////////////////////////////////////////////

    int n=0,tam=18;
    long enviados=0;
    Selecciona fil=new Selecciona();
    File f=fil.archivo();  
    //tipo para protocolo
    trama[12]= (byte) 0x16; //tipo sin asignar
    trama[13]= (byte) 0x01; //tipo sin asignar rfc 1340 
    //nombre del documento
    String nombre=fil.nom(f);
    byte[]buf = nombre.getBytes();
    tam = buf.length;
    final int tchec=1025;
    final byte[]check=new byte[tchec];
    if(tam>18){
        System.out.println("\nEl tamano del titulo es muy grande maximo 15 caracteres");
        System.exit(1);
    }
    else{
    long tamf=f.length();
    int tmax=1004; 
    //para la division del archivo
    String nombreC=f.getAbsolutePath();
    DataInputStream dis;
    dis = new DataInputStream(new FileInputStream(nombreC));
    //guarda el nombre del archivo
    for(int c=0;c<tam;c++){
                trama[15+c]=(byte)buf[c];
                check[c]=(byte)buf[c];
    }
    int con=0;
    //bite para tramas consecutivas
    int ndivi=(int)tamf/tmax,divi=1;
    if((tamf%tmax)!=0)
        ndivi++;
    while (enviados<tamf&&tam<=18){
        if(tamf>enviados){
            //define si la trama tiene o no mas partes
            //Si es uno el archivo contiene mas partes si es 0 es la ultima parte
            if(divi<ndivi){
                trama[33]=(byte)0x01;
                check[18]=(byte)0x01;
            }
            else {
                trama[33]=(byte)0x00;
                check[18]=(byte)0x00;
            } //numero de divisiones en las que secciono el archivo 
            trama[34]=(byte)ndivi;
            check[19]=(byte)ndivi;
            //numero de division del arhivo
            trama[35]=(byte)divi;
            check[20]=(byte)divi;
            //guarda el archivo en la trama seccionado
            byte[] arch=new byte [tmax];
            n=dis.read(arch);
            for (int j=0;j<tmax;j++){
                trama[36+j]=(byte)arch[j];
                check[21+j]=(byte)arch[j];
            }
            enviados=enviados+n;          
            divi++;
        }
        long calchec=Checksum.calculateChecksum(check,tchec);  

        //checksum
        trama[14]=(byte)calchec;  
    
    

    //Arrays.fill(a, (byte) 0xff);  
    ByteBuffer b = ByteBuffer.wrap(trama);  
  
    
  
    
    
    /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression ="ether proto 0x1601"; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			
        public void nextPacket(PcapPacket packet, String user) {

				System.out.printf("Paquete recibido el %s bytes capturados=%-4d tam original=%-4d %s\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                                /******Desencapsulado********/
              
            System.out.println("MAC destino:");
            for(int i=0;i<6;i++){
                System.out.printf("%02X ",packet.getUByte(i));
            }
            System.out.println("");
            System.out.println("MAC origen:");
            for(int i=6;i<12;i++){
                System.out.printf("%02X ",packet.getUByte(i));
            }
            System.out.println("");
            System.out.println("Tipo:");
            for(int i=12;i<14;i++){
                System.out.printf("%02X ",packet.getUByte(i));
            }
            int tipo = (packet.getUByte(12)*256)+packet.getUByte(13);
            System.out.printf("Tipo= %d",tipo);
            if(tipo==5633){ //0x1601
                 String nomf="";
                final byte [] datos=new byte [1004];
                final byte[] check=new byte[1025];
                for(int i=0;i<1025;i++)
                check[i]=(byte)packet.getUByte(i+15);
                long chec=Checksum.calculateChecksum(check, 1025);
                if((byte)chec==(byte)packet.getUByte(14))
                    System.out.printf("\nChecksum: %02X ",packet.getUByte(14));
                System.out.println("\nnombre del archivo: ");
                char c[]=new char [18];
                int ii=0;
                while(ii<18 && packet.getUByte(ii+15)!=0x00){
                    c[ii]=(char)(packet.getUByte(ii+15)&0xFF);
                    System.out.print(c[ii]);//imprime los caracteres
                    nomf=nomf+c[ii];
                    ii++;
                }
                
                for(int i=0;i<1004;i++){
                    datos[i]=(byte)packet.getUByte(i+36);
                }
                Recrea.crea(datos, nomf);
            }//if
            else 
                System.out.println("trama con errores");
        }
		};
    //pcap.loop(1, jpacketHandler, "");
    /******************************************************* 
     * Fourth We send our packet off using open device 
     *******************************************************/  
    
        //if (pcap.sendPacket(b) != Pcap.OK) {  
//        if(pcap.inject(b)<0){
            if (pcap.sendPacket(trama) != Pcap.OK) {  
          System.err.println(pcap.getErr());  
        }
            System.out.println("\nEnvie un paquete******");
        try{
            Thread.sleep(500);
        }catch(InterruptedException e){}
        pcap.loop(1, jpacketHandler, "");
    }//for
    /******************************************************** 
     * Lastly we close 
     ********************************************************/  
    pcap.close();  
    }
   }catch(Exception e){
       e.printStackTrace();
   }//catch
  }  
}    
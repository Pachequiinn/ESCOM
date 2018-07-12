   package paquete;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

public class Recrea {
    
    public  static void crea(byte[] buf,String nombre) {
        int tmax=1004;//tamaño de prueba 
            File archivo=new File(nombre);
 
        try{        
            BufferedOutputStream escribir=new BufferedOutputStream(new FileOutputStream(archivo,true));
            for(int i=0;i <tmax;i++){
                //if ((int)buf[i]!=0x00)
                escribir.write(buf[i]);
            }
            escribir.close();
        }        
        catch (Exception e){
            System.out.println(e);
        };
    }
}
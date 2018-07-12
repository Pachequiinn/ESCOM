package paquete;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

public class Selecciona {
    
    public String nom(File f){
    return f.getName();}
    
    public File archivo(){
        try{
            JFileChooser arch = new JFileChooser();
            int r=arch.showOpenDialog(null);//arch=archivo
            if(r==JFileChooser.APPROVE_OPTION){
                File f = arch.getSelectedFile();
                return f;
            }         
        }        
        catch (Exception e){};   
        return null;
    }
    
    public void datos(File f){
        int tmax=1400;
        try{
        long tam=f.length();
        String nombreC=f.getAbsolutePath();
        DataInputStream dis;
        dis = new DataInputStream(new FileInputStream(nombreC));
            if(tam>tmax){
                long enviados=0;
                while(enviados<tam){
                    byte[] b=new byte [tmax];
                    int n=dis.read(b);
                    for(int i=0;i <1400;i++){//funcion importante para convertir de byte a char
                        char c=(char)(b[i]&0xFF);
                        System.out.print(c);//imprime los caracteres
                    }
               // dis.close();
                }            
            }        
        }
        catch     (Exception e){};  
   }
}
    

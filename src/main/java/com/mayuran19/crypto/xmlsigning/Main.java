package com.mayuran19.crypto.xmlsigning;

/**
 * Created by mayuran on 28/11/16.
 */
public class Main {
    public static void main(String args[]) throws Exception{
        XMLSigningService xmlSigningService = new XMLSigningService();
        xmlSigningService.signDocument();
    }
}

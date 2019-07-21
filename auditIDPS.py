#!/usr/bin/python
# -*- coding: utf-8 -*-

#Pendientes
#1. Terminar puertos                           OK
#2. UDP                                        OK
#3. Descarga reglas
#4. Ayuda                                      OK  
#5. Parámetro "blanco"                         OK
#6. Script python formal __init__ __main__     OK
#7. C2CMDSAL agregar comando de salida         OK
#8. Reglas comentadas                          OK  
#9. Contar TCP/UDP                             OK
#10. Limpiar (dirs Snort que no van y lineas)  OK
#11. Verbose/Verbal                            OK
#12. Puertos faltantes
#13. Documentar
#14. Marca tiempo                              OK

# Documentacion:
# $ python -V: Python 2.7.10

#Regla de ejemplo:
# alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SERVER-WEBAPP WordPress login denial of service attempt"; 
#    flow:to_server,established; content:"wp-postpass_"; fast_pattern:only; content:"wp-postpass_"; http_cookie; 
#    content:"|25|24P|25|24Spaddding"; http_cookie; detection_filter:track by_src, count 500, seconds 5; metadata:service http; 
#    reference:url,seclists.org/bugtraq/2013/Jun/41; classtype:denial-of-service; sid:26981; rev:3;)
import getopt, sys
import re
import time
import os
from glob import glob
import socket
import datetime


# Variables
#####################################################################################

# Control socket
TIMEOUT = 1
# Directorio de reglas
dir_base = "."
# Contador de ataques totales, pruebas
cont1 = 0
# Contador de ataques exitosos
cont2 = 0
# Contador de ataques fallidos
cont3 = 0
# Contador de reglas con errores de proto (otro TCP/UDP)
cont4 = 0
# Contador de ataques exitosos TCP
cont5 = 0
# Contador de reglas comentadas para modo estricto (-s)
cont6 = 0


# Lista de puertos
#HTTP_PORTS = [36,80,81,82,83,84,85,86,87,88,89,90,311,383,555,591,593,631,801,808,818,901,972,1158,1220,1414,1533,1741,1830,1942,2231,2301,2381,2578,2809,2980,3029,3037,3057,3128,3443,3702,4000,4343,4848,5000,5117,5250,5600,5814,6080,6173,6988,7000,7001,7005,7071,7144,7145,7510,7770,7777,7778,7779,8000,8001,8008,8014,8015,8020,8028,8040,8080,8081,8082,8085,8088,8090,8118,8123,8180,8181,8182,8222,8243,8280,8300,8333,8344,8400,8443,8500,8509,8787,8800,8888,8899,8983,9000,9002,9060,9080,9090,9091,9111,9290,9443,9447,9710,9788,9999,10000,11371,12601,13014,15489,19980,29991,33300,34412,34443,34444,40007,41080,44449,50000,50002,51423,53331,55252,55555,56712]
#HTTP_PORTS = [36,80,443]
HTTP_PORTS = [80]
#SHELLCODE_PORTS !80
#ORACLE_PORTS 1024:
SSH_PORTS = [22]
#FTP_PORTS = [21,2100,3535]
#FTP_PORTS = [21,2100,3535]
#SIP_PORTS = [5060,5061,5600]
#FILE_DATA_PORTS = [36,80,81,82,83,84,85,86,87,88,89,90,311,383,555,591,593,631,801,808,818,901,972,1158,1220,1414,1533,1741,1830,1942,2231,2301,2381,2578,2809,2980,3029,3037,3057,3128,3443,3702,4000,4343,4848,5000,5117,5250,5600,5814,6080,6173,6988,7000,7001,7005,7071,7144,7145,7510,7770,7777,7778,7779,8000,8001,8008,8014,8015,8020,8028,8040,8080,8081,8082,8085,8088,8090,8118,8123,8180,8181,8182,8222,8243,8280,8300,8333,8344,8400,8443,8500,8509,8787,8800,8888,8899,8983,9000,9002,9060,9080,9090,9091,9111,9290,9443,9447,9710,9788,9999,10000,11371,12601,13014,15489,19980,29991,33300,34412,34443,34444,40007,41080,44449,50000,50002,51423,53331,55252,55555,56712,110,143]
#FILE_DATA_PORTS = [36]
#GTP_PORTS = [2123,2152,3386]


# Funciones
#####################################################################################

def linea(): #program does nothing as written
    print("-------------------------------------------------------")

def separador():    
    print("#######################################################")

def espacio(): #program does nothing as written
    print(" ")

def fataque1 (puerto,patron,c2cmd,c2cmdsal):
    global cont1,cont2,cont3, cont5
    if verbose == True:
        linea()
        print "Datos del Ataque:     "
        print "- Objetivo:           " + HOST
        print "- Puerto:             " + str(puerto)
        print "- Proto.:             " + proto
        print "- Patron:             " + patron
        print "- Comando C2:         " + c2cmd.encode('string_escape')
        print "- Comando C2 Salida:  " + c2cmdsal
    else:
        pass
    
    puerto = int(puerto)
    
    #------------------------------------------------------
    if proto in ['tcp']: 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        try:
            s.connect((HOST, puerto))
            s.settimeout(None)
            s.send(c2cmd)
            data = s.recv(1024)
            #s.close()
            if verbose == True:
                espacio()
                print 'Resultado del ataque: '
                print repr(data)
            else:
                pass
            s.send(patron)
            s.send(c2cmdsal)
            #data = s.recv(1024)
            s.close()
            if verbose == True: print "CX cerrada"
            cont2 += 1
            cont5 += 1
            #print 'Resultado del ataque: ', repr(data)     

        except IOError:
            cont3 += 1
            if verbose == True: print "NO ha sido posible establecer una conexión con [" + HOST + "] en el puerto [" + str(puerto) + "]"
            
    elif proto in ['udp']:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        try:
            s.connect((HOST, puerto))
            s.settimeout(None)
            #s.send(c2cmd)
            #data = s.recv(1024)
            #s.close()
            #print 'Resultado del ataque: '
            #print repr(data)
            s.send(patron)
            s.send(c2cmdsal)
            time.sleep(5)
            #data = s.recv(1024)
            s.close()
            #sock.shutdown(1)
            if verbose == True: print "CX cerrada"
            cont2 += 1
            #print 'Resultado del ataque: ', repr(data)     

        except IOError:
            cont3 += 1
            if verbose == True: print "NO ha sido posible establecer una conexión con [" + HOST + "] en el puerto [" + str(puerto) + "]"
             
    
    else:
        pass
        #espacio()
        #print "ERROR: Protocolo no especificado (TCP/UDP)." 
    #------------------------------------------------------
    
    cont1 += 1    


def uso():
    espacio()
    print "Uso del comando: ./auditIDPS.py [opciones, ] -t/--target HOST_IP/FQDN"
    print "    donde [opciones]:"
    print "    -v/--verbose: Activa la salida en pantalla con detalles de cada ataque."
    print "    -s/--strict: Activa la opción estricta, cumple política del IDPS."
    espacio()
    print "Autor: Juan Manuel Mosso <jmanuel@bacchuss.com.ar>, 2016."
    espacio()

    
def main():
    global HOST
    global estricto
    global verbose
    estricto = False
    
    espacio()    
    separador()
    print "Auditoria de Sistemas IDPS v.1.0"
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hot:vs", ["help", "output=", "target=", "strict="])
    except getopt.GetoptError as err:
        # imprime info de ayuda y sale
        print str(err)  # imprime cosas como "option -a not recognized"
        uso()
        sys.exit(2)
    output = None
    verbose = False
    for o, a in opts:
        if o == "-v":
            verbose = True
            print "Modo verbal:          Activado"
        elif o in ("-h", "--help"):
            uso()
            sys.exit()
        elif o in ("-o", "--output"):
            output = a
            print "Output" + output
        elif o in ("-t", "--target"):
            HOST = a
            linea()
            print "Objetivo:             " + HOST
        elif o in ("-s", "--strict"):
            estricto = True
            print "Modo estricto:        Activado"
        else:
            assert False, "unhandled option"
    


#######################################################################
# INICIO 

if __name__ == "__main__":
    # Toma de parametros de entrada y ayuda de la herramienta
    main()

tini = datetime.datetime.now()

# se recorre el directorio de snort que contiene las reglas (bajado o puesto a mano)
directorio = [y for x in os.walk(dir_base) for y in glob(os.path.join(x[0], '*.rules'))]

#En linea1 tenemos el nombre del archivo de reglas en el directorio de trabajo de reglas
for linea1 in directorio:        
 n = re.search('so_rules', linea1)
 m = re.search('preproc_rules', linea1)
 o = re.search('etc', linea1)
 
 
 if n or m or o:  #  Saltando directorio 'so_rules', decoder', 'preprocessor', y 'sensitive-data'
  pass
    
 else:
  ataque = re.sub(r'\.rules$', '', linea1)
  ataque = re.sub(r'\.\/snortrules-snapshot-.*\/rules/', '', ataque)       
  linea()
  linea()
  print "Reglas de ataque:     " + ataque
  
  
  #apertura del archivo para lectura, en linea2 guardamos las reglas 1x1
  aa = open(linea1, "r")       
  for linea2 in aa:
      
      #Detecta reglas comentadas, aplica a modo "-e/--estricto" en el que se ignoran las reglas comentadas
      p3 = re.search('^#*\salert', linea2)
        
      if p3:
           #print "Regla comentada XXX" + str(p3)
           cont6 += 1
      else:
           p3 = 'NOCOM'
           #print "Regla NO comentada XXX" + str(p3)
      
      
      m = re.search('content:"(.+?)"', linea2)
      #if m and (estricto == False or ((not p3) and estricto == True)):
      if m and (estricto == False or (estricto == True and p3 == 'NOCOM')):
        patron = m.group(1)         #definimos el patron de ataque en base a la regex 'm'

#Detecta el protocolo en las reglas (TCP/UDP)
        p0 = re.search('alert\s(.+?)\s', linea2)
        proto = p0.group(1)
            
#Detecta reglas que vienen con número de puerto especificado (ej.: 25)
        p1 = re.search('->\s\$.+\s([0-9]+?)\s\(', linea2)

#Detecta reglas que vienen con puerto por variable *_PORTS (ej.: HTTP_PORTS)
        p2 = re.search('->\s\$.+\s\$(.+?)_PORTS', linea2)   
            
#Procesa las reglas en base a p1, p2        
        if p1 and (proto == 'tcp' or proto == 'udp'):
            pesp = p1.group(1)
            pesp = int(pesp)
            if pesp in (25,587): 
                c2cmd = 'EHLO'
                c2cmdsal = 'QUIT'
            elif pesp in (80,443): 
                c2cmd = "GET / HTTP/1.0\r\n\r\n"
                c2cmdsal = 'QUIT'
            elif pesp == 110: 
                c2cmd = 'EHLO'
                c2cmdsal = 'QUIT'
            else:
                c2cmd= 'EHLO'
                c2cmdsal = 'QUIT'
            fataque1 (pesp,patron,c2cmd,c2cmdsal)        
        
        elif p2 and (proto == 'tcp' or proto == 'udp'):
            pgrp = p2.group(1)  
            #print "Este es el puerto:"
            #print pgrp
            
            #HTTP_PORTS           
            if pgrp in ['HTTP']:
                #print "PUERTO HTTP..."
                for puertoX in HTTP_PORTS:
                    #print puertoX
                    time.sleep(0.2)
                    c2cmd= 'GET / HTTP/1.0\r\n\r\n'
                    c2cmdsal = 'QUIT'
                    fataque1 (puertoX,patron,c2cmd,c2cmdsal)
        
            #SSH_PORTS           
            elif pgrp in ['SSH']:
                #print "PUERTO SSH..."
                for puertoX in SSH_PORTS:
                    #print puertoX
                    time.sleep(0.2)
                    c2cmd= ''
                    c2cmdsal = 'QUIT'
                    fataque1 (puertoX,patron,c2cmd,c2cmdsal)
           
           #FTP_PORTS           
            elif pgrp in ['FTP']:
                #print "PUERTO SSH..."
                for puertoX in FTP_PORTS:
                    #print puertoX
                    time.sleep(0.2)
                    c2cmd= 'HELO'
                    c2cmdsal = 'QUIT'
                    fataque1 (puertoX,patron,c2cmd,c2cmdsal)
            
            #SIP_PORTS           
            elif pgrp in ['SIP']:
                #print "PUERTO SSH..."
                for puertoX in SIP_PORTS:
                    #print puertoX
                    time.sleep(0.2)
                    c2cmd= 'HELO'
                    c2cmdsal = 'QUIT'
                    fataque1 (puertoX,patron,c2cmd,c2cmdsal)
            
            #FILE_DATA           
            elif pgrp in ['FILE_DATA']:
                #print "PUERTO SSH..."
                for puertoX in FILE_DATA_PORTS:
                    #print puertoX
                    time.sleep(0.2)
                    c2cmd= 'HELO'
                    c2cmdsal = 'QUIT'
                    fataque1 (puertoX,patron,c2cmd,c2cmdsal)
            
            #GTP           
            elif pgrp in ['GTP']:
                #print "PUERTO SSH..."
                for puertoX in GTP_PORTS:
                    #print puertoX
                    time.sleep(0.2)
                    c2cmd= 'HELO'
                    c2cmdsal = 'QUIT'
                    fataque1 (puertoX,patron,c2cmd,c2cmdsal)
            
            else:
                espacio()
                print "ERROR -> No ha sido posible determinar la variable de servicio de TI objetivo."
                espacio()
                
        else:
            cont4 += 1
            linea()
            if verbose == True: print "Error -> Protocolo no utilizable: " + proto   
            pass
        
  aa.close()

#print cont1, cont2, cont3
linea()
separador()

tfin = datetime.datetime.now()

contudp = cont2 - cont5
cont1 = str(cont1)
cont2 = str(cont2)
cont3 = str(cont3)
cont4 = str(cont4)
cont5 = str(cont5)
cont6 = str(cont6)
print "Resultados:"
print "- Fecha y hora:              " + str(datetime.datetime.now())
print "- Tiempo total de ejecucion:             " + str(tfin - tini)
print "- Pruebas totales:...................................." + cont1
print "- Ataques exitosos contra el IDPS:...................." + cont2
print "                      Ataques TCP:...................." + cont5
print "                      Ataques UDP:...................." + str(contudp)
print "- Ataques fallidos (sin CX) contra el IDPS:..........." + cont3
print "- Pruebas con error de protocolo:....................." + cont4
print "- Cantidad de reglas comentadas (modo estricto):......" + cont6
linea() 
espacio()   
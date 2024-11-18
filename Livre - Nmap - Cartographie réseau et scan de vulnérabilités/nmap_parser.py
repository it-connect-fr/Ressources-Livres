#!/usr/bin/python3
# -*- coding: utf-8 -*-
# coding=utf8
# Author : Mickael Dorigny (IT-Connect.fr)

import xml.etree.ElementTree as ET


def get_scan_info(element):
    """
    Affiche les informations générales du scan.

    Args:
        element (Element): L'élément racine du fichier XML.
    """
    scan_scanner = element.attrib.get('scanner')
    scan_args = element.attrib.get('args')
    scan_startstr = element.attrib.get('startstr')
    scan_version = element.attrib.get('version')
    print(f"- Date du scan : {scan_startstr}")
    print(f"- Version de nmap : {scan_version}")
    print(f"- Arguments : {scan_args}")


def list_scanned_host(element):
    """
    Affiche la liste des hôtes scannés.

    Args:
        element (Element): L'élément racine du fichier XML.

    Usage:
        list_scanned_host(nmaprun)
    """
    for host in element.findall('host'):
        ip_address = host.find('address').get('addr')
        print(f"[+] Host : {ip_address}")


def list_scanned_ports(element):
    """
    Affiche la liste des hôtes scannés et leurs ports.

    Args:
        element (Element): L'élément racine du fichier XML.

    Usage:
        list_scanned_ports(nmaprun)
    """
    for host in element.findall('host'):
        ip_address = host.find('address').get('addr')
        print(f"[+] Host : {ip_address}")

        # Itération sur tous les éléments "port"
        for port in host.findall('ports/port'):
            # Récupération de l'état du port
            state = port.find('state').get('state')

            # Récupération du numéro de port et protocole
            port_number = port.get('portid')
            protocol = port.get('protocol')
            print(f"  - {protocol}/{port_number} : {state}")


def get_host_from_service(element, searched_port):
    """
    Récupère la liste des hôtes ayant un service ouvert sur un port donné.

    Args:
        element (Element): L'élément racine du fichier XML.
        searched_port (int): Le numéro de port à rechercher.

    Returns:
        list: Liste des adresses IP des hôtes ayant le port ouvert.

    Usage:
        get_host_from_service(nmaprun, 22)
    """
    host_list = []
    for host in element.findall('host'):
        for port in host.findall('ports/port'):
            # Récupération de l'état du port
            if port.find('state').get('state') == "open" and port.get('portid') == str(searched_port):
                host_list.append(host.find('address').get('addr'))
    return host_list


def get_scan_results(element):
    """
    Affiche la liste des hôtes scannés, leurs ports ouverts, et les services.

    Args:
        element (Element): L'élément racine du fichier XML.

    Usage:
        get_scan_results(nmaprun)
    """
    for host in element.findall('host'):
        # Récupération de l'adresse IP
        ip_address = host.find('address').get('addr')
        print(f"[+] Host : {ip_address}")

        for port in host.findall('ports/port'):
            state = port.find('state').get('state')

            # Si le port n'est pas ouvert, on continue
            if state != "open":
                continue

            # Récupération du numéro de port et protocole
            port_number = port.get('portid')
            protocol = port.get('protocol')
            print(f"\t- {protocol}/{port_number} : open")

            # Récupération des informations de service si disponibles
            try:
                service = port.find('service').get('name')
                product = port.find('service').get('product')
                version = port.find('service').get('version')
                extrainfo = port.find('service').get('extrainfo')
                print(f"\t\t> {service} - {product} {version}")
            except AttributeError:
                service = None
                product = None
                version = None
                extrainfo = None

            # Récupération du CPE si disponible
            try:
                cpe = port.find('service').find('cpe').text
                print(f"\t\t> {cpe}")
            except AttributeError:
                cpe = ""


def import_nmap_xml(file):
    """
    Importe un fichier XML Nmap et retourne son élément racine.

    Args:
        file (str): Chemin vers le fichier XML.

    Returns:
        Element: L'élément racine du fichier XML.

    Usage:
        nmaplist_scanned_hostlist_scanned_hostrun = import_nmap_xml(“/mon/fichier.xml”)
    """
    tree = ET.parse(file)
    nmaprun = tree.getroot()
    return nmaprun

#!/usr/bin/env python3

import argparse
import logging
import os
import shutil
import subprocess
import sys
import threading

from pathlib import Path
from zipfile import ZipFile

from bs4 import BeautifulSoup


PROGRESS = 0
TOTAL = 0


def sanitize_host(host: str):
    # remove ., :, /, // if exist in host

    if '.' in host:
        host = ''.join(host.split('.'))
    if ':' in host:
        host = ''.join(host.split(':'))
    if '/' in host:
        host = ''.join(host.split('/'))
    if '//' in host:
        host = ''.join(host.split('//'))
    return host


def extract_nmap_xml(filename):
    xml_file = open(filename, 'r')
    soup = BeautifulSoup(xml_file, 'xml')
    urls = []
    for host in soup.find_all('host'):
        hostname = host.address["addr"]
        hnames = host.find_all('hostname')
        if hnames:
            hostname = hnames[0]["name"]
            if hostname[len(hostname)-1] == ".":
                hostname = hostname[:len(hostname)-1]
        if not host.ports:
            continue
        for port in host.ports.find_all('port'):
            if port.state["state"] == "open":
                service = port.find("service")
                if service and "http" in service["name"]:
                    if port.service.has_attr('tunnel') and service["tunnel"] == "ssl" or "https" in service["name"]:
                        url = "https://"
                    else:
                        url = "http://"
                    url += hostname + ":" + port["portid"]
                    urls.append(url)
                    print(f"Adding {url}")
    return urls


def take_screenshots(url_set: list, nb_threads):
    global PROGRESS
    for url in url_set:
        try:
            hostname = url.split("://")[1].split(":")[0]
            port = url.split("://")[1].split(":")[1]
            sc_file = 'pics/' + hostname + "-" + port + ".png"
            PROGRESS += 1
            print(f"[{PROGRESS}/{TOTAL}] Downloading: {url} > {sc_file}")
            devnull = open(os.devnull, 'w')
            subprocess.run(['phantomjs', '--ssl-protocol=any', '--ignore-ssl-errors=true', '../sc.js', url, sc_file],
                           stdout=devnull,
                           stderr=devnull)
            devnull.close()
        except Exception as exc:
            logging.exception(f"Screenshot exception : {exc}")


def generate_report(urls: list, nb_threads: int = 5, report_name: str = "report.html"):
    os.makedirs("pics/")
    html_file = open(report_name, "w")
    html_file.write('''
    <html>
    <head>
    </head>
    <body style="background: black">
    <table>
    '''
    )
    col = 0
    for url in urls:
        hostname = url.split("://")[1].split(":")[0]
        port = url.split("://")[1].split(":")[1]
        # sc_file = 'pics/' + hostname + "-" + port + ".png"
        sc_file = f'pics/{hostname}-{port}.png'
        if col == 0:
            html_file.write('<tr>')
        file = f'<td style="text-align:center">' \
               f'<div style="overflow:hidden"><a target="_blank" href="{url}">' \
               f'<img style="height:60%;width:80%;background:white;" src="{sc_file}"/></a><strong>' \
               f'<a target="_blank" href="{url}" style="color: white">{url}</a></strong></div></td>'
        html_file.write(file)
        if col == 3:
            html_file.write('</tr>')
        col = (col + 1) % 4
    html_file.write('''
    </table>
    </body>
    </html>
    '''
    )
    html_file.close()
    thread_load = len(urls) // nb_threads
    threads = []
    for i in range(nb_threads):
        if i == (nb_threads - 1):
            threads.append(
                threading.Thread(
                    target=take_screenshots,
                    args=(
                        urls[i * thread_load:], nb_threads
                    )
                )
            )
        else:
            threads.append(
                threading.Thread(
                    target=take_screenshots,
                    args=(
                        urls[i * thread_load:(i + 1) * thread_load], nb_threads
                    )
                )
            )

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    print(f"[*] Report generated: file:// {os.path.join(os.getcwd(), report_name)}")


def get_all_file_paths(directory):
    # initializing empty file paths list
    file_paths = []

    # crawling through directory and subdirectories
    for root, directories, files in os.walk(directory):
        for filename in files:
            # join the two strings in order to form the full filepath.
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)

    # returning all file paths
    return file_paths


def zip_dir(host: str):
    # sanitize host
    host = sanitize_host(host)

    # path to folder which needs to be zipped
    directory = '.' # current directory then, os.chdir() method is invoked

    # calling function to get all file paths in the directory
    file_paths = get_all_file_paths(directory)

    # printing the list of all files to be zipped
    print('Following files will be zipped:')
    for file_name in file_paths:
        print(file_name)

    try:
        # writing files to a zipfile
        with ZipFile(f'{host}.zip', 'w') as zip:
            # writing each file one by one
            for file in file_paths:
                zip.write(file)
        print('All files zipped successfully!')
        print(f"[*] File Location: file:// {os.path.join(os.getcwd())}")
    finally:
        # remove all files that do not end with .zip
        for file_path in file_paths:
            if not file_path.endswith('.zip'):
                Path(file_path).unlink(missing_ok=True)


def main():
    print(f"<=====================Start=====================>")
    parser = argparse.ArgumentParser(description="Generates an HTML report with screenshots of all Web applications from an XML nmap scan.")
    parser.add_argument("file", help="Nmap XML output")
    parser.add_argument("host", help="Host name or IP address")
    parser.add_argument("-t", "--threads", help="Number of threads")
    parser.add_argument("-o", "--output", help="Name of the generated report")

    args = parser.parse_args()

    # Open nmap file and extract Web applications URLs
    if not os.path.exists(args.file):
        print(f"File not found: {args.file}")
        sys.exit(0)

    with open(args.file, "r") as f:
        for line in f:
            if "<!DOCTYPE nmaprun>" in line:
                break
        else:
            print("Not a valid nmap XML")
            sys.exit(1)

    urls = extract_nmap_xml(args.file)

    print("Web applications: ")
    print("=" * 40)
    for url in urls:
        print(url)
    print("=" * 40)

    global TOTAL
    TOTAL = len(urls)

    # Generate the report
    report_name = "bigbrowser_report"
    if args.output:
        report_name = args.output
    if os.path.exists(report_name):
        # Recursively delete a directory tree if it exists
        shutil.rmtree(report_name)

        # if input(f"Folder exists {report_name} overwrite ?(y/n)").lower() == "y":
        #     shutil.rmtree(report_name)
        # else:
        #     sys.exit(1)

    # make directory
    os.makedirs(report_name)

    # change directory
    os.chdir(report_name)

    if args.threads:
        nb_threads = int(args.threads)
    else:
        nb_threads = 4

    generate_report(urls, nb_threads, report_name=f'{report_name}.html')
    zip_dir(args.host)
    print(f"<=====================Stop=====================>")


if __name__ == "__main__":
    main()

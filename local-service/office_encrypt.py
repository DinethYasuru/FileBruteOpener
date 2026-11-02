#!/usr/bin/env python3
"""Generates password-protected .docx/.xlsx/.pptx sample files via a headless LibreOffice
UNO session. Real Agile-encrypted Office Open XML files (CFB/OLE2-wrapped), openable in
Word/Excel/PowerPoint or decryptable with msoffcrypto-tool - not a synthetic approximation.

Usage: python3 office_encrypt.py <output_dir> <password>

Requires: libreoffice (soffice) and python3-uno, both already installed in this environment.
"""
import subprocess
import sys
import time

import uno
from com.sun.star.beans import PropertyValue

UNO_PORT = 2002


def make_prop(name, value):
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


def connect():
    proc = subprocess.Popen(
        ['soffice', '--headless', '--invisible', '--nocrashreport', '--nodefault',
         '--norestore', '--nologo', '--nofirststartwizard',
         f'--accept=socket,host=localhost,port={UNO_PORT};urp;'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    local_ctx = uno.getComponentContext()
    resolver = local_ctx.ServiceManager.createInstanceWithContext(
        'com.sun.star.bridge.UnoUrlResolver', local_ctx)
    for _ in range(30):
        try:
            ctx = resolver.resolve(
                f'uno:socket,host=localhost,port={UNO_PORT};urp;StarOffice.ComponentContext')
            return proc, ctx
        except Exception:
            time.sleep(1)
    proc.terminate()
    raise RuntimeError('Could not connect to headless LibreOffice.')


def main():
    if len(sys.argv) != 3:
        print('Usage: python3 office_encrypt.py <output_dir> <password>')
        sys.exit(1)
    out_dir, password = sys.argv[1], sys.argv[2]
    text = 'This document was encrypted for authorized password-recovery testing.'

    proc, ctx = connect()
    try:
        smgr = ctx.ServiceManager
        desktop = smgr.createInstanceWithContext('com.sun.star.frame.Desktop', ctx)
        jobs = [
            ('private:factory/swriter', f'{out_dir}/sample-office.docx', 'MS Word 2007 XML', 'writer'),
            ('private:factory/scalc', f'{out_dir}/sample-office.xlsx', 'Calc MS Excel 2007 XML', 'calc'),
            ('private:factory/simpress', f'{out_dir}/sample-office.pptx', 'Impress MS PowerPoint 2007 XML', 'impress'),
        ]
        for factory_url, out_path, filter_name, kind in jobs:
            doc = desktop.loadComponentFromURL(factory_url, '_blank', 0, (make_prop('Hidden', True),))
            if kind == 'writer':
                doc.getText().setString(text)
            elif kind == 'calc':
                doc.getSheets().getByIndex(0).getCellByPosition(0, 0).setString(text)
            elif kind == 'impress':
                doc.DrawPages.getByIndex(0).getByIndex(0).setString(text)
            doc.storeToURL('file://' + out_path,
                            (make_prop('FilterName', filter_name), make_prop('Password', password)))
            doc.close(False)
            print(f'wrote {out_path}')
    finally:
        proc.terminate()


if __name__ == '__main__':
    main()

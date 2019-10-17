import os
import core

from plugins.testHandler import XssRunner
from plugins.HTMLreport import *
from core.utils import load_yaml

def generate_xss_runner(data):
    data = load_yaml(data)    
    XssTest = XssRunner()

    for index,i in enumerate(data):
        for key,val in i.items():
            print(key)
            if key == 'global':
                for row in val:
                    XssTest.setGlobal(row)
            elif key == 'test':
                XssTest.setTest(val)
            elif key ==  'pilot':
                print(val)
                XssTest.doomBots.append(DoomBot(val))
                
    XssTest.runTests()
    return XssTest

def handle_report(xss_tests):
    tests = xss_tests.tests
    report_items = list()
    for item in tests:
        report_items.append(item.task)

    reports = generate_report(report_items)
    page = HTMLPage()
    page.reports = reports
    rep_page = page.envelop_report(page.reports)
    rep_page = page.insert_to_div(rep_page,conf={"class":"row"})
    rep_page = page.insert_to_div(rep_page,conf={"class":"container"})
    page_val = page.report_page(rep_page)
    return page_val
import re
import concurrent.futures
from urllib.parse import urlparse

from core.dom import dom
from core.log import setup_logger
from core.utils import getUrl, getParams, clean_colors
from core.requester import requester
from core.zetanize import zetanize
from plugins.retireJs import retireJs

logger = setup_logger(__name__)


def photon(seedUrl, headers, level, threadCount, delay, timeout, skipDOM):
    forms = []  # web forms
    processed = set()  # urls that have been crawled
    storage = set()  # urls that belong to the target i.e. in-scope
    schema = urlparse(seedUrl).scheme  # extract the scheme e.g. http or https
    host = urlparse(seedUrl).netloc  # extract the host e.g. example.com
    main_url = schema + '://' + host  # join scheme and host to make the root url
    print(seedUrl)
    storage.add(seedUrl)  # add the url to storage
    checkedDOMs = []

    report_vulnerabilities = list()


    def rec(target):

        vulnerable_items = list()
        vulnerable_report = dict()

        processed.add(target)
        printableTarget = '/'.join(target.split('/')[3:])
        if len(printableTarget) > 40:
            printableTarget = printableTarget[-40:]
        else:
            printableTarget = (printableTarget + (' ' * (40 - len(printableTarget))))
        logger.run('Parsing %s\r' % printableTarget)
        url = getUrl(target, True)
        params = getParams(target, '', True)
        if '=' in target:  # if there's a = in the url, there should be GET parameters
            inps = []
            for name, value in params.items():
                inps.append({'name': name, 'value': value})
            forms.append({0: {'action': url, 'method': 'get', 'inputs': inps}})
        response = requester(url, params, headers, True, delay, timeout).text
        vulnerable_components = retireJs(url, response)
        print("===== Vulnerable Components ======")
        print(vulnerable_components)
        vulnerable_report['vulnerable_components'] = vulnerable_components
        if not skipDOM:
            highlighted = dom(response)
            clean_highlighted = ''.join([re.sub(r'^\d+\s+', '', line) for line in highlighted])
            if highlighted and clean_highlighted not in checkedDOMs:
                checkedDOMs.append(clean_highlighted)
                logger.good('Potentially vulnerable objects found at %s' % url)
                vulnerable_report['url'] = url
                logger.red_line(level='good')
                for line in highlighted:
                    vulnerable_items.append(clean_colors(line))
                    logger.no_format(line, level='good')
                vulnerable_report['codes'] = vulnerable_items
                logger.red_line(level='good')
        forms.append(zetanize(response))
        matches = re.findall(r'<[aA].*href=["\']{0,1}(.*?)["\']', response)
        for link in matches:  # iterate over the matches
            # remove everything after a "#" to deal with in-page anchors
            link = link.split('#')[0]
            if link.endswith(('.pdf', '.png', '.jpg', '.jpeg', '.xls', '.xml', '.docx', '.doc')):
                pass
            else:
                if link[:4] == 'http':
                    if link.startswith(main_url):
                        storage.add(link)
                elif link[:2] == '//':
                    if link.split('/')[2].startswith(host):
                        storage.add(schema + link)
                elif link[:1] == '/':
                    storage.add(main_url + link)
                else:
                    storage.add(main_url + '/' + link)
        return vulnerable_report
    for x in range(level):
        urls = storage - processed  # urls to crawl = all urls - urls that have been crawled
        # for url in urls:
        #     rec(url)
        threadpool = concurrent.futures.ThreadPoolExecutor(
            max_workers=threadCount)
        futures = (threadpool.submit(rec, url) for url in urls)
        for i in concurrent.futures.as_completed(futures):
            try:
                report_tmp = i.result()
            except Exception as e:
                print(str(e))
                pass
            else:
                check = False
                for i in report_tmp.values():
                    check = check or bool(i)
                if check:
                    report_vulnerabilities.append(report_tmp)
    return ([forms, processed],report_vulnerabilities)

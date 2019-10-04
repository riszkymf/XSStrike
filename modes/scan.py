import copy
import re
from urllib.parse import urlparse, quote, unquote

from core.arjun import arjun
from core.checker import checker
from core.colors import good, bad, end, info, green, red, que
import core.config
from core.config import xsschecker, minEfficiency
from core.dom import dom
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.utils import getUrl, getParams, getVar
from core.wafDetector import wafDetector
from core.log import setup_logger

logger = setup_logger(__name__)


def scan(target, paramData, encoding, headers, delay, timeout, skipDOM, find, skip):
    reports = {}
    GET, POST = (False, True) if paramData else (True, False)
    # If the user hasn't supplied the root url with http(s), we will handle it
    if not target.startswith('http'):
        try:
            response = requester('https://' + target, {},
                                 headers, GET, delay, timeout)
            target = 'https://' + target
        except:
            target = 'http://' + target
    logger.debug('Scan target: {}'.format(target))
    response = requester(target, {}, headers, GET, delay, timeout).text
    vulnerable_code = list()
    if not skipDOM:
        logger.run('Checking for DOM vulnerabilities')
        highlighted = dom(response)
        if highlighted:
            logger.good('Potentially vulnerable objects found')
            logger.red_line(level='good')
            for line in highlighted:
                vulnerable_code.append(line)
                logger.no_format(line, level='good')
            logger.red_line(level='good')
    potential_vulnerabilities = [{"code" : vulnerable_code}]
    reports["potential_vulnerabilities"] = potential_vulnerabilities
    host = urlparse(target).netloc  # Extracts host out of the url
    logger.debug('Host to scan: {}'.format(host))
    url = getUrl(target, GET)
    logger.debug('Url to scan: {}'.format(url))
    params = getParams(target, paramData, GET)
    logger.debug_json('Scan parameters:', params)
    if find:
        params = arjun(url, GET, headers, delay, timeout)
    if not params:
        logger.error('No parameters to test.')
        reports['parameter_reports'] = "No parameters to test."
        return reports
    WAF = wafDetector(
        url, {list(params.keys())[0]: xsschecker}, headers, GET, delay, timeout)
    if WAF:
        logger.error('WAF detected: %s%s%s' % (green, WAF, end))
    else:
        logger.good('WAF Status: %sOffline%s' % (green, end))
    paramReports = list()
    for paramName in params.keys():
        paramReport = {
            "parameter": None,
            "encoding": None,
            "reflection": None
        }
        paramReport['parameter'] = paramName
        paramsCopy = copy.deepcopy(params)
        logger.info('Testing parameter: %s' % paramName)
        if encoding:
            paramsCopy[paramName] = encoding(xsschecker)
            paramReport['encoding'] = str(encoding)
        else:
            paramsCopy[paramName] = xsschecker
        response = requester(url, paramsCopy, headers, GET, delay, timeout)
        occurences = htmlParser(response, encoding)
        positions = occurences.keys()
        logger.debug('Scan occurences: {}'.format(occurences))
        if not occurences:
            logger.error('No reflection found')
            paramReport['reflection'] = "No reflection found"
            continue
        else:
            logger.info('Reflections found: %i' % len(occurences))
            paramReport['reflection'] = len(occurences)

        logger.run('Analysing reflections')
        efficiencies = filterChecker(
            url, paramsCopy, headers, GET, delay, occurences, timeout, encoding)
        logger.debug('Scan efficiencies: {}'.format(efficiencies))
        logger.run('Generating payloads')
        vectors = generator(occurences, response.text)
        total = 0
        for v in vectors.values():
            total += len(v)
        if total == 0:
            logger.error('No vectors were crafted.')
            continue
        logger.info('Payloads generated: %i' % total)
        paramReport['payloads_generated'] = total
        payloadLists = list()
        progress = 0
        for confidence, vects in vectors.items():
            for vect in vects:
                payloaditem = {}
                if core.config.globalVariables['path']:
                    vect = vect.replace('/', '%2F')
                loggerVector = vect
                progress += 1
                logger.run('Progress: %i/%i\r' % (progress, total))
                if not GET:
                    vect = unquote(vect)
                try:
                    efficiencies = checker(
                        url, paramsCopy, headers, GET, delay, vect, positions, timeout, encoding)
                except Exception as e:
                    payloaditem['error'] = str(e)
                    print("ERROR")
                    continue
                if not efficiencies:
                    for i in range(len(occurences)):
                        efficiencies.append(0)
                bestEfficiency = max(efficiencies)
                if bestEfficiency == 100 or (vect[0] == '\\' and bestEfficiency >= 95):
                    logger.red_line()
                    logger.good('Payload: %s' % loggerVector)
                    logger.info('Efficiency: %i' % bestEfficiency)
                    logger.info('Confidence: %i' % confidence)
                    if not skip:
                        choice = input(
                            '%s Would you like to continue scanning? [y/N] ' % que).lower()
                        if choice != 'y':
                            quit()
                elif bestEfficiency > minEfficiency:
                    logger.red_line()
                    logger.good('Payload: %s' % loggerVector)
                    logger.info('Efficiency: %i' % bestEfficiency)
                    logger.info('Confidence: %i' % confidence)
                payloaditem['payload'] = loggerVector
                payloaditem['efficiency'] = bestEfficiency
                payloaditem['confidence'] = confidence
                payloadLists.append(payloaditem)
                print(payloaditem)
        paramReport['payload_reports'] = payloadLists
        logger.no_format('')
    reports['parameter_reports'] = paramReport
    return reports
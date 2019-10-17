import copy
from urllib.parse import urlparse, unquote
from core.colors import good, green, end
from core.requester import requester
from core.utils import getUrl, getParams
from core.log import setup_logger


logger = setup_logger(__name__)


def bruteforcer(target, paramData, payloadList, encoding, headers, delay, timeout):
    report = list()
    GET, POST = (False, True) if paramData else (True, False)
    host = urlparse(target).netloc  # Extracts host out of the url
    logger.debug('Parsed host to bruteforce: {}'.format(host))
    url = getUrl(target, GET)
    logger.debug('Parsed url to bruteforce: {}'.format(url))
    params = getParams(target, paramData, GET)
    logger.debug_json('Bruteforcer params:', params)
    if not params:
        logger.error('No parameters to test.')
        return report
    for paramName in params.keys():
        report_payloads = dict()
        progress = 1
        paramsCopy = copy.deepcopy(params)
        report_payloads['parameter'] = paramName
        report_payloads['passing_payloads'] = list()
        for payload in payloadList:
            logger.run('Bruteforcing %s[%s%s%s]%s: %i/%i\r' %
                       (green, end, paramName, green, end, progress, len(payloadList)))
            if encoding:
                payload = encoding(unquote(payload))
            paramsCopy[paramName] = payload
            response = requester(url, paramsCopy, headers,
                                 GET, delay, timeout)
            response = response.text
            if encoding:
                payload = encoding(payload)
            
            if payload in response or payload in unquote(response):
                report_payloads['passing_payloads'].append(payload)
                logger.info('%s %s' % (good, payload))
            progress += 1
        report.append(report_payloads)
    logger.no_format('')
    return report

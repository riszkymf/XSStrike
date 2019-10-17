class XssArgsParser(object):
    pass

class GlobalSettings(object):
    
    def __init__(self):
        self.globalPostData = PostData()
        self.globalHeaders = {}
        self.globalPayload = list()
        self.globalProxies = {}
        self.globalTargets = None
        self.globalXssConfig = XssConfig()
    
    def setValue(self,items):
        key = list(items.keys())[0]
        if key == 'headers':
            self.setHeaders(items)
        elif key == 'target':
            self.setTarget(items[key])
        elif key == 'payload':
            self.setPayload(items)
        elif key == 'xss_config':
            self.setXssConfig(flatten_dictionaries(items[key]))
    
    def setTarget(self,targetData):
        target = None
        self.globalTargets = TargetHandler(targetData)            
    
    def setHeaders(self,headersData):
        postData = self.globalPostData
        postData.setValue(headersData)
        
    def setPayload(self,payloadData):
        postData = self.globalPostData
        postData.setValue(flatten_dictionaries(payloadData))
        
    def preparePayload(self):
        postdata = self.globalPostData
        if not postdata.headers:
            postdata.headers = config.headers
        postdata.preparePostData()
        
    def setXssConfig(self,item):
        config = self.globalXssConfig
        for key,val in item.items():
            setattr(config,key,val)
        self.globalXssConfig = config
        

class TargetHandler(object):
    """Used to handle target, could be list of url/path or str"""
    
    target = None
    _multitarget = None
    multitarget = None
    
    def __init__(self,target):
        if isinstance(target,str):
            self.target = dict()
            __target = self.classify(target)
            self.target[__target] = target
        elif isinstance(target,list):
            self._multitarget = {'url' : list(), 'file': list()}
            self.multitarget = list()
            for item in target:
                __target = self.classify(item)
                if __target in list(self._multitarget.keys()):
                    self._multitarget[__target].append(item) 
                    if __target == 'url':
                        self.multitarget.append(item)
        for item in self._multitarget['file']:
            _target = list(filter(None,reader(item)))
            for row in _target:
                self.multitarget.append(row)
        
    def classify(self,targetvalue):
        targettype = None
        if validators.url(targetvalue):
            return "url"
        else:
            try:
                open(os.path.abspath(targetvalue))
            except Exception:
                msg = "File {} does not exist or unknown target value".format(targetvalue)
                print(os.path.abspath(targetvalue))
                print(color(msg,fore='red',style='bold'))
                return False
            else:
                return "file"

class XssConfig(object):
    
    def __init__(self):
        self.crawl = False
        self.crawlLevel = 2
        self.crawlThread = 10
        self.brute = False
        self.params = False
        self.timeout = 10
        self.delay = 0
        self.blind = False
        self.fuzzer = False
        self.proxies = {}
        self.skipDOM = False
        self.blindXSS = True
        self.jsonData = False
        self.path = False
        self.skip = False
        self.find = False
        
    @property
    def xssconfigs(self):
        d = {
            "crawl": self.crawl,
            "crawlLevel":self.crawlLevel,
            "crawlThread" :self.crawlThread,
            "brute": self.brute,
            "params": self.params,
            "timeout": self.timeout ,
            "delay" : self.delay,
            "blind" : self.blind,
            "fuzzer": self.fuzzer,
            "proxies": self.proxies,
            "skipDOM": self.skipDOM,
            "blindXSS": self.blindXSS,
            "jsonData": self.jsonData,
            "path": self.path,
            "skip": self.skip,
            "find": self.find
        }
        return d

class XssTests(GlobalSettings,XssConfig):
    test_name = "Default"
    
    def __init__(self):
        XssConfig.__init__(self)
        GlobalSettings.__init__(self)
        self._xssconfig_keys = list(self.xssconfigs.keys())
    
    def configureXssStrike(self,globalConfig=dict()):
        configKeys = self._xssconfig_keys
        conf = dict()
        TestConfig = self.globalXssConfig
        for key in configKeys:
            conf[key] = TestConfig.get(key,globalConfig.get(key))
        self.globalXssConfig = conf
        
    def setXssConfig(self,item):
        d = {}
        for key,val in item.items():
            d[key] = val
        self.globalXssConfig = d
        
    def setTarget(self,targetData):
        target = None
        self.globalTargets = TargetHandler(targetData)
        
    def inheritHeaders(self,globalHeaders):
        test_headers = self.globalPostData.headers
        new_headers = {**globalHeaders, **test_headers}
        self.globalPostData.headers = new_headers
        
    def inheritPayload(self,payload):
        __payloads = self.globalPostData        
        if payload.file:
            __payloads.file = __payloads.file +  payload.file
        if payload._payload:
            for key,val in payload.__payload.item():
                __payloads[key] = val
        self.globalPostData = __payloads
        
class TaskHandler(object):
    config = None
    task_type = None
    target = list()
    
    def setConfigGlobalVariables(self):
        core.config.globalVariables = dict()
        __cfg = {**self.config, **self.payload.payloadConfig}
        core.config.globalVariables = __cfg
        core.config.globalVariables['checkedScripts'] = set()
        core.config.globalVariables['checkedForms'] = {}
        core.config.globalVariables['definitions'] = json.loads('\n'.join(reader(os.getcwd() + '/db/definitions.json')))
        core.config.proxies = core.config.globalVariables['proxies']
        
    def __init__(self,config,target,payload):
        self.config = config
        self.target = target
        self.payload = payload
        self.task_type = None
        self.__setType()
        self.setConfigGlobalVariables()
        
    def __setType(self):
        target = self.target
        payload = self.payload
        if len(target.multitarget) == 1:
            if self.config['fuzzer']:
                self.task_type = 'fuzz'
            elif payload.file:
                self.task_type = 'bruteforcer'
            else:
                self.task_type = 'scan'
        else:
            self.config['crawl'] = True
            self.task_type = 'crawling'
            self.seedList = target.multitarget
            
    def undefined_task():
        print("Task {} does not exist, or task is not defined".format(self.task_type))
            
    def run_task(self):
        task_name = self.task_type
        print("Running {}".format(task_name))
        func = getattr(self,task_name,'undefined_task')
        func()
        
    
    def fuzzer(self):
        target = self.target.multitarget[0]
        encoding = self.payload.payloadEncoding
        headers = self.payload.headers
        delay = self.config['delay']
        paramData = self.payload.paramData
        timeout = self.config['timeout']
        singleFuzz(target, paramData, encoding, headers, delay, timeout)
            
    def crawling(self):
        seedList = self.seedList
        headers = self.payload.headers
        level = self.config['crawlLevel']
        delay = self.config['delay']
        skipDOM = self.config['skipDOM']
        threadCount = self.config['crawlThread']
        timeout = self.config['timeout']
        blindXSS = self.config['blindXSS']
        encoding = self.payload.payloadEncoding
        
        print(seedList)
        
        for target in seedList:
            scheme = urlparse(target).scheme
            logger.debug('Target scheme: {}'.format(scheme))
            host = urlparse(target).netloc
            main_url = scheme + '://' + host
            crawlingResult = photon(target, headers, level,
                                    threadCount, delay, timeout, skipDOM)
            forms = crawlingResult[0]
            domURLs = list(crawlingResult[1])
            difference = abs(len(domURLs) - len(forms))
            if len(domURLs) > len(forms):
                for i in range(difference):
                    forms.append(0)
            elif len(forms) > len(domURLs):
                for i in range(difference):
                    domURLs.append(0)
            threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=threadCount)
            futures = (threadpool.submit(crawl, scheme, host, main_url, form,blindXSS, blindPayload, headers, delay, timeout, encoding) for form, domURL in zip(forms, domURLs))
            for i, _ in enumerate(concurrent.futures.as_completed(futures)):
                if i + 1 == len(forms) or (i + 1) % threadCount == 0:
                    logger.info('Progress: %i/%i\r' % (i + 1, len(forms)))
            logger.no_format('')
            
    def bruteforcer(self):
        paramData = self.payload.paramData
        payloadList = self.payload.payload
        encoding = self.payload.payloadEncoding
        headers = self.payload.headers
        delay = self.config['delay']
        timeout = self.config['timeout']
        if not payloadList:
            payloadList = list(core.config.payloads)
        if not isinstance(payloadList,list):
            print("payloads need to be in list format!")
        for target in self.target.multitarget:
            bruteforcer(target, paramData, payloadList, encoding, headers, delay, timeout)
        
    def scan(self):
        paramData = self.payload.paramData
        encoding = self.payload.payloadEncoding
        headers = self.payload.headers
        delay = self.config['delay']
        timeout = self.config['timeout']
        skipDOM = self.config['skipDOM']
        skip = self.config['skip']
        find = self.config['find']
        target = self.target.multitarget[0]
        scan(target, paramData, encoding, headers, delay, timeout, skipDOM, find, skip)
        
class PostData(object):
    payload = None
    headers = None
    
    def __init__(self):
        self._payload = {}
        self.payload = {}
        self.headers = {}
        self.payloadConfig = {}
        self.paramData = None
        self.file = list()

        
    def setValue(self,data):
        headers = dict()
        _payload = dict()
        for key,value in data.items():
            if key == 'headers':
                self.setHeaders(flatten_dictionaries(data[key]))
            elif key == 'payload':
                self.setPayload(flatten_dictionaries(data[key]))
        
    def setHeaders(self,data):
        d = {}
        for key,value in data.items():
            d[key] = value
        self.headers = d
        
    def updateHeaders(self,headersKey,headersValue):
        self.headers.update({headersKey:headersValue})
        
    def setPayload(self,data):
        config = data.get('config',None)
        self.setPayloadConfig(config)
        _payload = list()
        if 'dict' in data:
            payloadData = flatten_dictionaries(data.get('data',[]))
            payload = {}
            for key,value in payloadData.items():
                payload[key] = value
            self._payload = payload
        elif 'string' in data:
            if isinstance(data['string'],str):
                self.paramData = data['string']
            else:
                self._payload = data['string']
        elif 'file' in data:
            self.payloadConfig['path'] = True
            if data['file'].lower() == 'default':
                self.file = defaultPayloads
            else:
                self.file = list(filter(None, reader(data['file'])))
        
    def preparePostData(self):
        config = self.payloadConfig
        isjson = config.get('jsonData',False)
        isencoded = config.get('encode',False)
        if isjson:
            self.updateHeaders('Content-type','application/json')
            self.paramData = json.dumps(self._payload)
            self.payloadConfig['jsonData'] = True
        else:
            self.payload = self._payload
        self.payloadConfig['paramData'] = self.payload
        if isencoded:
            self.payloadEncoding = base64
        else :
            self.payloadEncoding = False
        
    def setPayloadConfig(self,data):
        config = {}
        if data:
            for i in data:
                if isinstance(i,str):
                    config[i] = True
                elif isinstance(i,dict):
                    config.update(i)
                else:
                    continue
        self.payloadConfig.update(config)
        
        
class XssRunner(object):
    xssconfig = None
    globalsettings = None
    tests = list()
    
    def __init__(self):
        self.globalsettings = GlobalSettings()
        self.tests = list()
        
    def setGlobal(self,value):
        self.globalsettings.setValue(value)
        
    def setTest(self,value):
        test = XssTests()
        for row in value:
            test.setValue(row)
        test.configureXssStrike(self.globalsettings.globalXssConfig.xssconfigs)
        test.inheritPayload(self.globalsettings.globalPostData)
        test.inheritHeaders(self.globalsettings.globalPostData.headers)
        test.preparePayload()
        test.task = TaskHandler(test.globalXssConfig,test.globalTargets,test.globalPostData)
        test.task.setConfigGlobalVariables()
        self.tests.append(test)

    def GlobalTestGenerator(self):
        """Add tests from global targets"""
        test_case = list()
        _globalconfig = self.globalsettings
        test = XssTests()
        test.globalTargets = _globalconfig.globalTargets
        test.globalXssConfig = _globalconfig.globalXssConfig
        test.globalPostData=_globalconfig.globalPostData
        test.preparePayload()
        test.task = TaskHandler(test.globalXssConfig.xssconfigs,test.globalTargets,test.globalPostData)
        test.task.setConfigGlobalVariables()
        test_case.append(test)
        return test_case
        
    def runTests(self):
        for test in self.tests:
            task = test.task
            task.run_task()
    
    
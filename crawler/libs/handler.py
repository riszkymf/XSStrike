import yaml
import json
import json
import hashlib 

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from crawler.libs.util import *
from crawler.libs.extractors import *

from time import sleep

"""
Product Crawler class inherit company details from Company Details class.
It will generate crawlers which will be appended to Worker's tasks list"""


DRIVER_PATH = {"chrome": get_path('chromedriver'),
               "firefox": get_path('geckodriver')}


class Worker(object):

    driverType = "chrome"
    driverPath = DRIVER_PATH['chrome']
    driver = None
    is_headless = True
    task_ = list()

    def __init__(self,headless=True, *args, **kwargs):
        task_ = list()
        options = Options()
        if headless:
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--user-agent='Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'")        
        self.driver = webdriver.Chrome(self.driverPath, options=options)

    def get(self,url):
        self.driver.get(url)
        self.action = ActionChains(self.driver)


class DoomBot(object):
    product_name = None
    endpoint = None
    type_ = None
    content = list()
    worker = None
    driver = None
    failure_count = 0
    is_template_path = False
    is_template_content = False
    with_action = False
    chain_query = list()
    display = None
    skip = False
    content_result = list()
    is_headless = False
    dump_to_database = True
    status_html_content = False
    status_crawler = False
    ignore_none = None
    currency_used = None
    window_size = False

    def __init__(self, config, *args, **kwargs):
        super(ProductCrawler, self).__init__(**config)
        self.content = {}
        self.action_chains = list()
        self.chain_query = list()
        self.date_time = get_time()
        for key, value in kwargs.items():
            if key == 'name':
                self.product_name = value
            elif key == 'endpoint':
                self.endpoint = value
            elif key == 'type':
                self.type_ = value
            elif key == 'data_display':
                self.display = value
            elif key == 'content':
                for i in value:
                    content_ = self.parse_content(i)
                    self.content = {**self.content, **content_}
            elif key == 'skip_first_data':
                self.skip = True
            elif key == 'currency_used':
                self.currency_used = value
            elif key == 'dump_to_database':
                self.dump_to_database = value
            elif key == 'is_headless':
                self.is_headless = value
            elif key == 'ignore_none':
                self.ignore_none = value
            elif key == 'window_size':
                try:        
                    value = flatten_dictionaries(value)
                    self.window_size_x = int(value['x'])
                    self.window_size_y = int(value['y'])
                    self.window_size = True
                except Exception:
                    pass
            elif key == 'action_chains':
                chain_query = list()
                self.with_action = True
                for i in value:
                    for key, val in i.items():
                        chain_name = key
                        chain = self.parse_action_chains(val)
                        d = {'chain_name': chain_name, 'chain': chain}
                    self.chain_query.append(d)
            else:
                raise ValueError("Wrong Configuration")
    @property
    def product_detail(self):
        time = get_time()
        d = {
            "nm_product_type": self.type_,
            "nm_product_name": self.product_name,
            "nm_endpoint": self.endpoint,
            "datetime": str(time),
            "content" : None
        }
        return d

    def write_result(self,crawl_result):
        self.content_result = (crawl_result)

    def crawler_result(self):
        result = self.product_detail
        result['content'] = self.content_result
        return result

    def get_url(self):
        return self.base_url + self.endpoint

    def is_dynamic(self):
        """ Is templating used? """
        return self.is_template_path or self.is_template_content

    def config_worker(self):
        self.worker = Worker(self.is_headless)
        worker = self.worker
        url = self.get_url()
        worker.get(url)
        wait = get_loaded(worker.driver)
        if not wait:
            print("Page not loaded")
        self.driver = worker.driver
        if self.window_size:
            print("Resizing {} x {}".format(self.window_size_x,self.window_size_y))
            self.driver.set_window_size(int(self.window_size_x),int(self.window_size_y))
        else:
            self.driver.maximize_window()
        self.action = worker.action
        self.config_action_chains()

    def config_action_chains(self):
        if self.with_action:
            action_chains = list()
            chain = self.chain_query
            for i in range(0,len(chain)):
                _iter = chain[i]
                tmp = ActionsHandler(self.action, self.driver, 
                                     _iter['chain'], _iter['chain_name'])
                action_chains.append(tmp)
            self.action_chains = action_chains

    def obtain_value(self):
        contents = self.content
        for k, v in contents.items():
            for i in v:
                i.extractor.driver = self.driver

    def parse_action_chains(self, actions):
        chains = list()
        for action in actions:
            for act, query in action.items():
                d = {}
                q_ = flatten_dictionaries(query)
                d[act] = q_
                chains.append(d)    
        return chains

    def parse_content(self, content=list()):
        content_handler = list()
        contents = ContentHandler(content)
        return contents.get_value()

    def check_html_changes(self):
        new_content = self.get_html_content()
        old_content = self.html_content
        if not old_content:
            self.get_html_content(dump=True)
            return True
        elif new_content != old_content:
            msg = "Content changed detected on endpoint : {}\nOld:{}\nNew:{}".format(self.endpoint,old_content,new_content)
            print(msg)
            self.get_html_content(dump=True)
            self.status_html_content = False
            return False
        else :
            self.status_html_content = True
            return True


    def get_html_content(self,dump=False):
        url = self.get_url()
        try:
            content = get_page(url)
            content = content.text.encode('utf-8')
            content = hashlib.sha224(content).hexdigest()
        except Exception as e:
            tmp_worker = Worker(headless=True)
            driver = tmp_worker.driver
            driver.get(url)
            elem = driver.find_element_by_xpath("//body")
            content = elem.get_attribute("innerHTML")
            content = content.encode('utf-8')
            content = hashlib.sha224(content).hexdigest()
            driver.quit()
        if dump:
            filename = self.endpoint.replace("/","__")
            filename = "{}_{}".format(self.company_name,filename) + ".txt"
            file_path = "{}/{}".format(HTML_LOCATION,filename)
            file_path = get_path(file_path)
            generate_file(file_path,content)
        else:
            return content

    @property
    def html_content(self):
        try:
            filename = self.endpoint.replace('/','__')
            filename = "{}_{}".format(self.company_name,filename) + ".txt"
            path = '{}/{}'.format(HTML_LOCATION,filename)
            pathfile = get_path(path)
            data = read_file(pathfile)
            if data:
                return data
            else:
                return None
        except Exception as e:
            return None

    def filter_ignored(self,data,ignore_value=None):
        ignore_value = self.ignore_none
        if not ignore_value:
            return data
        else:
            result = list()
            for i in data:
                is_pass = True
                for key in ignore_value:
                    try:
                        if i[key].lower() == 'none' or i[key] == '':
                            is_pass = False
                            break
                    except Exception:
                        continue
                if is_pass:
                    result.append(i)
            return result

#   Obtain data for every action in action chains. 
    def run(self):
        count = 0
        self.check_html_changes()
        print(self.get_url())
        if self.action_chains:
            self.obtain_value()
            data = list()
            if not self.skip:
                data.append(self.write_value())
            for action in self.action_chains:
                for i in range(0, action.repeat):
                    action.run()
                    self.obtain_value()
                    data.append(self.write_value())
        else:
            self.obtain_value()
            data = [(self.write_value())]
        return data

    def warm_up(self):
        action = self.action_chains[0]
        action.run()

    def write_value(self):
        data = dict()
        for key, value in self.content.items():
            val = list()
            for item in value:
                if item.is_preaction:
                    item._configure_preactions(self.action,self.driver)
                content_ = item.dump_value()
                val.append(content_)
            data[key] = flatten_list(val)
        return data 

    def sort_data(self,data):
        for row in data:
            pass
    
    def normalize(self,data):
        displayType = self.display
        result_tmp = None
        if displayType == 'slider':
            tmp = DataSorter(data,displayType)
            result_tmp = tmp.sorted_data
        else:
            keys = list()
            resultTmp = list()
            for i in data:
                tmp = DataSorter(i,displayType)
                tmp_data = tmp.sorted_data
                resultTmp.append(tmp_data)
                tmp_key = [i for i in tmp_data.keys() if i not in keys ]
                keys += tmp_key
            d = {}
            for i in keys:
                d[i] = list()
                for row in resultTmp:
                    d[i] += row[i]
            result_tmp = d
        result = {}
        for key,value in result_tmp.items():
            result[key] = self.filter_ignored(value)
        return result

    def report_error(self):
        data = self.product_detail
        res = update_scraper_status("FAIL",data['nm_product_name'])
        return res

    def register_company(self):
        send_data = {
            "nm_company" : self.company_name,
            "url_company": self.base_url,
            "currency_used": self.currency_used
        }

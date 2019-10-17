from bs4 import BeautifulSoup,NavigableString
import os

class HTMLReport(object):
    raw_report = None
    
    def __init__(self,raw_report):
        self.raw_report = raw_report
        
        
    def generate_vector_table_result(self,data):
        _html = '<table class="table table-bordered table-hover"> <thead> <tr> <td class="_head" rowspan="2">vulnerable_webpage</td>'
        _html += '<td class="_head" colspan="2">vector_for</td> </tr> <tr> <td class="_head"> Vector Key</td> <td class="_head"> Vector Value</td> </tr></thead>'
        _html += '<tbody></tbody></table>'
        table = BeautifulSoup(_html,features="html.parser")
        _table = table.table
        _tbody = _table.tbody

        tbody =  table.new_tag("tbody")
        for row in data:
            _link = row['vulnerable_webpage']
            trow = table.new_tag("tr")
            tcell = table.new_tag("td")
            tcell.insert(0,NavigableString(_link))
            
            for key,value in row['vector_for'].items():
                tcell_2 = table.new_tag("td")
                tcell_2.insert(0,NavigableString(key))
                code = table.new_tag('code')
                code.string = NavigableString(value)
                tcell_3 = table.new_tag("td")
                tcell_3.append(code)
            trow.insert(0,tcell)
            trow.insert(1,tcell_2)
            trow.insert(2,tcell_3)
            _tbody.insert(0,trow)
        table.table.append(_tbody)
        
        card = BeautifulSoup('<div class="card"><div class="card-header">Vector Results</div><div class="card-body"></div></div>',features="html.parser")
        div = card.div.find_all('div')[1]
        div.append(table.table)
        return card
    
    
    
    def vulnerable_components(self,vulnerable_component,url_loc=""):
        #test = test_data_full[0]['potential_vulnerabilities']
        #_test = test[0]['vulnerable_components']
        div = BeautifulSoup('<div></div>',features="html.parser")

        info = BeautifulSoup('<div class="card"><div class="card-body"><span class="card-text info_component"></span></div></div>')
        for i in vulnerable_component:
            table = BeautifulSoup('<table class="table table-sm table-bordered"><thead><tr><td>Summary </td><td>Severity </td><td>CVE</td></tr></thead><tbody></tbody></table>',features="html.parser")
            _table = table.table
            ul = BeautifulSoup('<ul></ul>',features="html.parser")
            ul.ul['class'] = 'info_component'
            _content = "Vulnerable Component :   " + i['vulnerable_component']
            li = ul.new_tag('li')
            li.insert(0,NavigableString(_content))
            ul.ul.append(li)

            _content = "Component Location   :   " + i['component_location']
            li = ul.new_tag('li')
            ul.ul.append(li)
            li.insert(0,NavigableString(_content))

            _content = "Total Vulnerabilities   :   " + str(i['total_vulnerabilities'])
            li = ul.new_tag('li')
            ul.ul.append(li)
            li.insert(0,NavigableString(_content))

            _content = "Details : "
            li = ul.new_tag('li')
            li.insert(0,NavigableString(_content))


            ul.ul.append(li)
            info.div.div.span.append(ul)
            for item in i['details']:
                tr = table.new_tag('tr')
                for val in item.values():
                    cells = BeautifulSoup("<td>{} </td>".format(val),features="html.parser")
                    tr.append(cells)
                _table.tbody.append(tr)
            info.div.div.span.append(_table)
        card_header = div.new_tag('div',**{"class": "card-header"})
        card_header.append("Vulnerable Components : {} ".format(url_loc))
        info.div.insert(0,card_header)
        return info
            
    def generate_config_report(self,config):
        table = BeautifulSoup('<table class="table table-sm table-bordered"><thead><tr><th colspan="2" class="_head"></th></tr></thead><tbody></tbody></table>',features="html.parser")
        table.table.thead.tr.th.append(NavigableString("Testing Configuration"))
        rows = list()
        hrows = list()
        payrows = list()
        for key,val in config.items():
            row = table.new_tag('tr')
            if key.lower() == 'headers':
                head_headers = table.new_tag('th')
                head_headers['scope'] = 'row'
                head_headers['colspan'] = '2'
                head_headers['class'] = "_head"
                head_headers.string = 'Headers'
                hrows.append(head_headers)
                for hkey,hval in val.items():
                    hrow = table.new_tag('tr')

                    hcell_key = table.new_tag('th')
                    hcell_key['scope'] = 'row'
                    hcell_key.string = NavigableString(hkey)
                    hrow.append(hcell_key)


                    hcell_val = table.new_tag('td')
                    p_val = table.new_tag('code')
                    p_val.string = NavigableString(hval)
                    hcell_val.append(p_val)
                    hrow.append(hcell_val)
                    hrows.append(hrow)
            elif key.lower() == 'payloadlist':
                payrow = table.new_tag('tr')
                head_headers = table.new_tag('th',**{'rowspan':str(len(val)), "scope": "row"})
                head_headers.append("Payload List")
                payrow.append(head_headers)
                for index,_code in enumerate(val):
                    td = table.new_tag('td')
                    pay_val = table.new_tag('code')
                    pay_val.string = NavigableString(_code)
                    td.append(pay_val)
                    if index == 0:
                        payrow.append(td)
                        payrows.append(payrow)
                    else:
                        _payrow = table.new_tag('tr')
                        _payrow.append(td)
                        payrows.append(_payrow)
            else:
                cell_key = table.new_tag('th')
                cell_key['scope'] = 'row'
                cell_key.string = key
                row.append(cell_key)

                cell_val = table.new_tag('td')
                cell_val.string = NavigableString(str(val))
                row.append(cell_val)
                rows.append(row)

        rows = rows + hrows + payrows

        for row in rows:
            table.table.tbody.append(row)
        return table
    
    def insert_to_div(self,element,conf=dict(),item=dict()):
        soup = BeautifulSoup("<div></div>",features="html.parser")
        div = soup.div
        for key,val in conf.items():
            div[key] = val
        if item:
            for key,val in item.items():
                if key == 'pre':
                    div.append(val)
        div.append(element)
        return div
    
    def generate_vulnerable_object(self,potential_vul): 
        soup = BeautifulSoup('<div class="card"></div>',features="html.parser")
        card = soup.div
        card_header = soup.new_tag('div',**{'class': 'card-header'})
        card_header.string = "Potentially Vulnerable Objects"
        card_body = soup.new_tag('div',**{'class': 'card-body'})
        card_text = soup.new_tag('p',**{"class": "card-text url_location"})
        card_text.append("URL : ")
        url = soup.new_tag('a',href=potential_vul['url'])
        url.string = potential_vul['url']
        card_text.append(url)
        codes = soup.new_tag('pre')
        for _code in potential_vul['codes']:
            pcode = soup.new_tag('p')
            code = soup.new_tag('code')
            code.string = _code
            pcode.append(code)
            codes.append(pcode)
        card_header.append(card_text)
        card_body.append(codes)
        card.append(card_header)
        card.append(card_body)
        return card

    def generate_div_report(self,report_data,config):
        soup = BeautifulSoup('<div class="card-body"></div>',features="html.parser")
        rowconfig = self.insert_to_div(config,{"class" : "col-11col-8"})
        colconfig = self.insert_to_div(rowconfig,{"class": "row"})
        for i in report_data:
            col_i = self.insert_to_div(i,{"class" : "col-12"})
            rowconfig.append(col_i)
        div = soup.div
        div.append(rowconfig)
        return div
    
    def envelop_report(self,report_div):
        soup = BeautifulSoup('<div class="card report-card col-11"></div>',features="html.parser")
        div_env = soup.div
        if isinstance(report_div,list):
            for item in report_div:
                div_env.append(item)
            return div_env
        else:
            div_env.append(report_div)
        return div_env
        
        
    def generate_pot_vulnerabilities(self,data=dict()):
        soup = BeautifulSoup('<html></html>',features="html.parser")
        reports = list()
        for key,val in data.items():
            if key == 'vulnerable_components' and val:
                tmp = self.vulnerable_components(val,data['url'])
                reports.append(tmp)
            elif key == 'codes':
                tmp = self.generate_vulnerable_object(data)
                reports.append(tmp)
        return reports
    
    def generate_fuzzer_report(self,fuzzer_data):
        soup = BeautifulSoup('<div class="card"><div class="card-body"></div></div>',features="html.parser")
        card = soup.div
        card_headers = soup.new_tag('div',**{"class": "card-header"})
        card_headers.append(NavigableString("Fuzzer Report"))
        card.append(card_headers)
        div = soup.div.div
        ul = soup.new_tag('ul')
        li = soup.new_tag('li')
        li.append("Target       :    {} ".format(fuzzer_data['config']['target']))
        ul.append(li)
        
        li = soup.new_tag('li')
        li.append("WAF Status   :    {} ".format(fuzzer_data['waf']))
        ul.append(li)
        table = soup.new_tag('table',**{"class":"table table-bordered"})

        params = fuzzer_data['parameters']

        thead = soup.new_tag("thead")
        tr_sub = soup.new_tag("tr",**{"class":"th-dark"})
        th_sub = soup.new_tag("th")
        th_sub.append("Parameter Value ")
        tr_sub.append(th_sub)
        th_sub = soup.new_tag("th")
        th_sub.append("Status ")
        tr_sub.append(th_sub)
        thead.append(tr_sub)
        tbody = soup.new_tag("tbody")
        for i in params:

            tr_param = soup.new_tag("tr",**{"class":"th-dark-param"})
            th_param = soup.new_tag("th",**{"colspan":"2","class":"sub-head"})
            th_param.append("Parameter : {} ".format(i['paramater']))
            tr_param.append(th_param)   
            tbody.append(tr_param)

            for item in i['result']:
                tr_result = soup.new_tag('tr')
                cell_string = soup.new_tag('td')
                cell_string.append(item['fuzz_string'])
                cell_stat = soup.new_tag('td')
                cell_stat.append(item['status'])

                tr_result.append(cell_string)
                tr_result.append(cell_stat)
                tbody.append(tr_result)
        table.append(thead)
        table.append(tbody)
        table = self.insert_to_div(table)
        conf = self.insert_to_div(ul,conf={"class":"fuzzer_conf"})
        div.append(conf)
        div.append(table)
        card.append(div)
        return card
    
    def generate_scan_parameter_table(self,data):
        soup = BeautifulSoup('<table class="table table-sm"><thead class="table-dark"></thead><tbody></tbody></table>',features="html.parser")
        thead = soup.table.thead
        tbody = soup.table.tbody
        
        tr = soup.new_tag('tr')
        th = soup.new_tag('th')
        th.append("parameter")
        tr.append(th)
        
        th = soup.new_tag('th',**{"colspan":"2"})
        th.append(NavigableString(data['parameter']))
        tr.append(th)
        thead.append(tr)
        
        tr = soup.new_tag('tr')
        th = soup.new_tag('th')
        th.append(NavigableString("Encoding"))
        tr.append(th)
    
        th = soup.new_tag('th',**{"colspan":"2"})
        th.append(NavigableString(str(data['encoding'])))
        tr.append(th)
        thead.append(tr)
        
        tr = soup.new_tag('tr')
        th = soup.new_tag('th')
        th.append(NavigableString("Reflection"))
        tr.append(th)
    
        th = soup.new_tag('th',**{"colspan":"2"})
        th.append(NavigableString(str(data['reflection'])))
        tr.append(th)
        thead.append(tr)
        
        tr = soup.new_tag('tr')
        th = soup.new_tag('th')
        th.append(NavigableString("Payload Generated"))
        tr.append(th)
    
        th = soup.new_tag('th',**{"colspan":"2"})
        th.append(NavigableString(str(data['payloads_generated'])))
        tr.append(th)
        thead.append(tr)
        
        tr = soup.new_tag('tr')
        th = soup.new_tag('th')
        th.append(NavigableString('payload'))
        tr.append(th)
        th = soup.new_tag('th')
        th.append(NavigableString('efficiency'))
        tr.append(th)
        th = soup.new_tag('th')
        th.append(NavigableString('confidence'))
        tr.append(th)
        
        thead.append(tr)
        
        for item in data['payload_reports']:
            tr = soup.new_tag('tr')
            th_payload = soup.new_tag('td')
            th_payload.append(NavigableString(item['payload']))
            th_efficiency = soup.new_tag('td')
            th_efficiency.append(NavigableString(str(item['efficiency'])))
            th_confidence = soup.new_tag('td')
            th_confidence.append(NavigableString(str(item['confidence'])))
            tr.append(th_payload)
            tr.append(th_efficiency)
            tr.append(th_confidence)
            tbody.append(tr)
        
        return soup.table
        
        
    def generate_scan_report(self,data):
        soup = BeautifulSoup('<div class="card"></div>',features="html.parser")
        card_head = soup.new_tag("div",**{"class":"card-header"})
        card_head.append(NavigableString("Scanning Result"))
        card_body = soup.new_tag("div",**{"class":"card-body"})
        table = self.generate_scan_parameter_table(data['parameter_reports'])
        card_body.append(table)
        soup.div.append(card_head)
        soup.div.append(card_body)
        return soup.div
        
    def generate_bruteforce_report(self,report):
        soup = BeautifulSoup('<div class="card"><div>',features="html.parser")
        card_header = soup.new_tag("div",**{"class":"card-header"})
        
        config = self.generate_config_report(report['config'])
        card_config = soup.new_tag("div",**{"class":"card"})
        card_config_head = soup.new_tag("div",**{"class":"card-header"})
        title = soup.new_tag('h5',**{"class":"card-title"})
        title.append(NavigableString("Bruteforce"))
        card_config_head.append(title)
        
        card_config_body = soup.new_tag("div",**{"class":"card-body"})
        card_config_body.append(config)
        card_config.append(card_config_head)
        card_config.append(card_config_body)
        
        
        soup.div.append(card_config)
        
        card_result = soup.new_tag('div',**{"class":"card"})
        card_result_head = soup.new_tag("div",**{"class":"card-header"})
        card_result_head.append(NavigableString("Result"))
        card_result.append(card_result_head)
        
        for i in report['result']:
            card_body = soup.new_tag('div',**{"class":"card-body"})
            if i['passing_payloads']:
                result_table = soup.new_tag('table',**{"class":"table table-sm"})
                thead = soup.new_tag('thead',**{"class":"table-success"})
                thead_text = "Passing Payloads for parameter {} ".format(i['parameter'])
                thead.append(NavigableString(thead_text))
                tbody = soup.new_tag('tbody')
                for payload in i['passing_payloads']:
                    tr = soup.new_tag('tr')
                    td = soup.new_tag('td')
                    code = soup.new_tag('code')
                    code.append(NavigableString(payload))
                    td.append(code)
                    tr.append(td)
                    tbody.append(tr)
                result_table.append(thead)
                result_table.append(tbody)
                card_body.append(result_table)
            else:
                alert = soup.new_tag('div',**{"class":"alert alert-success"})
                alert_message = "No Payload passed for parameter {}".format(i['parameter'])
                alert.append(NavigableString(alert_message))
                card_body.append(alert)
            card_result.append(card_body)
            br = soup.new_tag('br')
            card_result.append(br)
        
        soup.div.append(card_result)
        return soup.div
        
        


class HTMLPage(HTMLReport):
    
    def __init__(self):
        self.reports = list()
        self.styling = dict()

    @property
    def css_styling(self):
        default = {
            ".info_component":
            {
                "padding-left": "15px",
                "color": "#ad1548"
            },
            "._head , td._head":
            {
                "text-align":"center",
                "vertical-align":"middle"
            },
            ".url_location":{
                "float":"right"
            },
            ".th-dark":{
                "background-color": "#1f1f1f",
                "color": "rgb(243, 240, 235)"
            },
            ".th-dark-param":{
                "background-color": "#726d6d",
                "color": "white"
            },
            "th.sub-head":{
                "background-color": "#726d6d",
                "color": "white"
            }
        }
        new_style = {**default, **self.styling}
        css_text = ""
        for tag,style in new_style.items():
            attribute_val = tag + " {" + "\n"
            for key,val in style.items():
                attribute_val += key + ":" + val + ";" + "\n"
            attribute_val += "}" + "\n"
            css_text += attribute_val
        return css_text
    
    def report_page(self,full_report):
        soup = BeautifulSoup("""<!doctype html>
            <html lang="en">
              <head>
                <title>Xss Report</title>
                <!-- Required meta tags -->
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                <!-- Bootstrap CSS -->
                <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
                <style></style>
              </head>
              <body>
              </body>
            </html>""",features="html.parser")
        soup.html.head.style.append(self.css_styling)
        soup.html.body.append(full_report)
        return soup



def generate_report(tasks):
    reported = list()
    for task in tasks:
        data = task.TaskReport
        task_type = task.task_type
        report = HTMLReport(data)
        _res = list()
        if task_type == 'fuzzer':
            _res = generate_fuzzer_report(report)
        elif task_type == 'bruteforcer':
            _res = generate_bruteforce_report(report)
        elif task_type == 'scan':
            _res = generate_scan_report(report)
        elif task_type == 'crawling':
            _res = generate_crawling_report(report)
        reported += _res
    return reported    


def generate_fuzzer_report(report):
    return [report.generate_fuzzer_report(report.raw_report)]      

def generate_bruteforce_report(report):
    return [report.generate_bruteforce_report(report.raw_report[0])]

def generate_scan_report(report):
    return [report.generate_scan_report(report.raw_report)]

def generate_crawling_report(report):
    reports = list()
    for i in report.raw_report:
        _reports = list()
        _table = report.generate_vector_table_result(i['result'])
        _reports.append(_table)
        for j in i['potential_vulnerabilities']:
            _reports += report.generate_pot_vulnerabilities(j)
        conf = report.generate_config_report(i['config'])
        reps = report.generate_div_report(_reports,conf)
        reports.append(reps)
    card = BeautifulSoup('<div class="card"><div class="card-header"><h5 class="card-title">Crawling</h5></div></div>',features="html.parser")
    for i in reports:
        card.div.append(i)
    return [card]

    
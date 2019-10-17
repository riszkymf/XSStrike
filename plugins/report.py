class ReportHandler(object):

    task_type = None
    
    def __init__(self,task_type):
        self.config = dict()
        self.obtainedData = None
        self.task_type = task_type
    
    def setConfig(self,config):
        self.config.update(config)

    def setReportData(self,data):
        self.reportData = data

    
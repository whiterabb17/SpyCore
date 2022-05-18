using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNet.Objects;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;

namespace SpyCore
{
    class ReportStructure
    {
        public Dictionary<string, bool> ScanResults { get { return scanResults; } }
        public string VerboseMsg { get { return verboseMsg; } }
        public DateTime ScanDate { get { return scanDate; } }
        public FileReportResponseCode ResponseCode { get { return responseCode; } }
        public List<string> VirNames { get { return virNames; } }

        private static Dictionary<string, bool> scanResults = null;
        private string verboseMsg = null;
        private DateTime scanDate = DateTime.Now;
        private FileReportResponseCode responseCode = FileReportResponseCode.NotPresent;
        private static List<string> virNames = null;

        public static ReportStructure FromReport(FileReport report)
        {
            ReportStructure str = new ReportStructure();
            str.verboseMsg = report.VerboseMsg;
            str.scanDate = DateTime.Now;
            str.responseCode = report.ResponseCode;
            scanResults = new Dictionary<string, bool>();
            virNames = new List<string>();
            if(str.ResponseCode == FileReportResponseCode.Present)
            {
                foreach(KeyValuePair<string, ScanEngine> scan in report.Scans)
                {
                    scanResults.Add(scan.Key, scan.Value.Detected);
                    virNames.Add(scan.Value.Result);
                }
            }
            return str;
        } 
    }
}

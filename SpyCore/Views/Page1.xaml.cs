using LiveCharts;
using LiveCharts.Wpf;
using SpyCore.Helpers;
using SpyCore.ViewModels;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace SpyCore.Views
{
    /// <summary>
    /// Interaction logic for Page1.xaml
    /// </summary>
    public partial class Page1 : Page
    {
        public Page1(CommunityViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel;
            _APIkey = Properties.Settings.Default.VTAKey;
        }
        public static string _APIkey;
        private void pictureBox2_Click(object sender, RoutedEventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.InitialDirectory = "c:\\";
                openFileDialog.FilterIndex = 2;
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    //Get the path of specified file
                    var filePath = openFileDialog.FileName;
                    filePath_textbox.Text = filePath.ToString();
                    FileInfom.FileInfoInstance.File_Path = filePath.ToString();
                    FileInfom.FileInfoInstance.File_Name = openFileDialog.SafeFileName;

                    //Get all the file information
                    fileName_textbox.Text = FileInfom.FileInfoInstance.File_Name;
                    MD5_textbox.Text = Helpers.Utility.CalculateMD5(filePath);
                    SHA1_textbox.Text = Helpers.Utility.CalculateSHA1(filePath);
                    SHA256_textbox.Text = Helpers.Utility.CalculateSHA256(filePath);
                    size_textbox.Text = Helpers.Utility.CalculateFileSize(filePath).ToString() + " bytes";
                }
            }
        }

        private async void scan_button_Click(object sender, RoutedEventArgs e)
        {
                APIHelper.ApiClient.DefaultRequestHeaders.Add("x-apikey", Properties.Settings.Default.VTAKey);


            //TODO: check if file is larger than 33,554,432 bytes
            await GetScanResultsAsync();
        }

        /// <summary>
        /// Async method to create an HTTPPost request to scan the file the user selected. Scan results are filtered and saved
        /// </summary>
        /// <returns></returns>
        private async Task GetScanResultsAsync()
        {
            ScanResults scanResults = null;
            do
            {
                scanResults = await UploadFile.CreateScanReqAsync();

                if (scanResults.Data.Attributes.LastAnalysisResults.Count > 72)
                {
                    break;
                }
                else
                {
                    // if results are still not of expected size, wait 10 seconds and request them again
                    await Task.Delay(10000);
                }
            } while (true);

            int malicious = 0;
            int undetected = 0;
            int unknown = 0;
            if (scanResults != null)
            {
                foreach (KeyValuePair<string, LastAnalysisResult> entry in scanResults.Data.Attributes.LastAnalysisResults)
                {
                    // categorize the outcome of the scan result
                    if ((int)entry.Value.Category == 0)
                    {
                        malicious++;
                    }
                    else if ((int)entry.Value.Category == 1)
                    {
                        unknown++;
                    }
                    else if ((int)entry.Value.Category == 2)
                    {
                        undetected++;
                    }
                    else if ((int)entry.Value.Category == 3)
                    {
                        unknown++;
                    }
                    else if ((int)entry.Value.Category == 4)
                    {
                        unknown++;
                    }
                }

                Func<ChartPoint, string> labelPoint = chartPoint => string.Format("{0} ({1:P})", chartPoint.Y, chartPoint.Participation);
                SeriesCollection piechartData = new SeriesCollection
                {
                    new PieSeries
                    {
                        Title = "Malicious",
                        Values = new ChartValues<double> {malicious},
                        DataLabels = true,
                        LabelPoint = labelPoint,
                        Fill = System.Windows.Media.Brushes.Maroon
                    },
                    new PieSeries
                    {
                        Title = "Undetected",
                        Values = new ChartValues<double> {undetected},
                        DataLabels = true,
                        LabelPoint = labelPoint,
                        Fill = System.Windows.Media.Brushes.MediumBlue
                    },
                    new PieSeries
                    {
                        Title = "Unknown",
                        Values = new ChartValues<double> {unknown},
                        DataLabels = true,
                        LabelPoint = labelPoint,
                        Fill = System.Windows.Media.Brushes.Gray
                    }
                };
                malPercent.Content = "Malicious = " + malicious;
                safePercent.Content = "Safe = " + undetected;
                unkPercent.Content = "Unknown = " + unknown;
                pieChart1.Series = piechartData;
                CommunityVotesChart(scanResults.Data.Attributes.TotalVotes.Harmless, scanResults.Data.Attributes.TotalVotes.Malicious);
            }
        }


        /// <summary>
        /// Exit button to close application
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
       

        /// <summary>
        /// Builds a bar graph for the community votes.
        /// </summary>
        /// <param name="safeCount"></param>
        /// <param name="maliciousCount"></param>
        public void CommunityVotesChart(long safeCount, long maliciousCount)
        {
            /*
            chart1.Series.Clear();
            chart1.Series.Add("Safe");
            chart1.Series["Safe"].ChartType = DataVisualization.Charting.SeriesChartType.Bar;
            chart1.Series.Add("Malicious");
            chart1.Series["Malicious"].ChartType = System.Windows.Forms.DataVisualization.Charting.SeriesChartType.Bar;

            chart1.Series["Safe"].Color = Color.MediumBlue;
            chart1.Series["Malicious"].Color = Color.Maroon;

            if (safeCount < 1 && maliciousCount < 1)
            {
                chart1.Series.Clear();
                chart1.Series.Add("No Votes Found");
                chart1.Series["No Votes Found"].ChartType = System.Windows.Forms.DataVisualization.Charting.SeriesChartType.Bar;
                chart1.Series["No Votes Found"].Color = System.Drawing.Color.Gray;
                chart1.Series["No Votes Found"].Points.AddXY("No Votes Found", 1);
            }
            else
            {
            //no community votes found. Create default bar chart
                            chart1.Series["Safe"].Points.AddXY("2", safeCount);
                chart1.Series["Malicious"].Points.Add(0);
                            chart1.Series["Malicious"].Points.AddXY("1", maliciousCount);
            }
            */
        }
    }
}

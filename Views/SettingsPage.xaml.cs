using System.Windows.Controls;

using SpyCore.ViewModels;

namespace SpyCore.Views
{
    public partial class SettingsPage : Page
    {
        public SettingsPage(SettingsViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel;
        }

        private void saveKey_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            Properties.Settings.Default.VTAKey = apiKey.Text;
            Properties.Settings.Default.Save();
        }

        private void Page_Loaded(object sender, System.Windows.RoutedEventArgs e)
        {
            apiKey.Text = Properties.Settings.Default.VTAKey;
        }
    }
}

using System;
using System.Windows.Forms;

namespace NetScanner
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            ApplicationConfiguration.Initialize();
            Application.Run(new ScannerForm());
        }
    }
}

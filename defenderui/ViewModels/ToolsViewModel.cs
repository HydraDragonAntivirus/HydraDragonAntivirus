using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Models;
using DefenderUI.Services;

namespace DefenderUI.ViewModels;

#pragma warning disable MVVMTK0045

/// <summary>
/// Araçlar (Tools) sayfası için ViewModel. FeatureTileCard grid'ini
/// <see cref="FeatureTileData"/> listesiyle besler; her tile tıklamasında
/// toast gösterir (gerçek implementasyon Faz 7+).
/// </summary>
public partial class ToolsViewModel : ObservableObject
{
    private readonly IToastService? _toastService;

    [ObservableProperty]
    private ObservableCollection<FeatureTileData> _tools = new();

    public ToolsViewModel(IToastService? toastService = null)
    {
        _toastService = toastService;
        LoadTools();
    }

    private void LoadTools()
    {
        Tools = new ObservableCollection<FeatureTileData>
        {
            new(Glyph: "\uE74D", Title: "Güvenli Dosya Silme",
                Description: "Dosyaları kurtarılamayacak şekilde silin.",
                BadgeText: null, NavigateKey: "tool:shred"),
            new(Glyph: "\uE74C", Title: "Sistem Temizleyici",
                Description: "Gereksiz dosyaları ve önbelleği temizleyin.",
                BadgeText: null, NavigateKey: "tool:cleaner"),
            new(Glyph: "\uE7E8", Title: "Önyükleme Taraması",
                Description: "Sistem açılışında derin tarama yapın.",
                BadgeText: null, NavigateKey: "tool:boot-scan"),
            new(Glyph: "\uE785", Title: "Güvenli Açılış",
                Description: "Bilgisayarı güvenli modda başlatın.",
                BadgeText: "Yeni", NavigateKey: "tool:safe-boot"),
            new(Glyph: "\uE72E", Title: "Şifrelenmiş Dosya Kasası",
                Description: "Hassas dosyaları şifreli kasada saklayın.",
                BadgeText: null, NavigateKey: "tool:vault"),
            new(Glyph: "\uE968", Title: "Ağ Monitörü",
                Description: "Gerçek zamanlı ağ trafiğini izleyin.",
                BadgeText: null, NavigateKey: "tool:net-monitor"),
            new(Glyph: "\uE774", Title: "DNS Koruması",
                Description: "DNS sorgularını güvence altına alın.",
                BadgeText: null, NavigateKey: "tool:dns"),
            new(Glyph: "\uE8D7", Title: "Parola Denetleyici",
                Description: "Zayıf parolaları tespit edin.",
                BadgeText: null, NavigateKey: "tool:pwd-check"),
            new(Glyph: "\uE8B7", Title: "Arşiv Tarayıcı",
                Description: "ZIP/RAR içindeki dosyaları tarayın.",
                BadgeText: null, NavigateKey: "tool:archive"),
        };
    }

    [RelayCommand]
    private void LaunchTool(string? toolKey)
    {
        if (string.IsNullOrWhiteSpace(toolKey))
        {
            return;
        }

        var title = toolKey switch
        {
            "tool:shred" => "Güvenli Dosya Silme",
            "tool:cleaner" => "Sistem Temizleyici",
            "tool:boot-scan" => "Önyükleme Taraması",
            "tool:safe-boot" => "Güvenli Açılış",
            "tool:vault" => "Şifrelenmiş Dosya Kasası",
            "tool:net-monitor" => "Ağ Monitörü",
            "tool:dns" => "DNS Koruması",
            "tool:pwd-check" => "Parola Denetleyici",
            "tool:archive" => "Arşiv Tarayıcı",
            _ => "Araç"
        };

        _toastService?.Info(title, "Bu özellik yakında kullanılabilir olacak.");
    }
}

#pragma warning restore MVVMTK0045
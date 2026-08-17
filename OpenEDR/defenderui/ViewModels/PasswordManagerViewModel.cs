using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Services;

namespace DefenderUI.ViewModels;

#pragma warning disable MVVMTK0045

/// <summary>
/// Parola Yöneticisi tanıtım (teaser) sayfası VM'si. Gerçek depolama YOK;
/// yalnızca özellik listesi ve "kurulum" CTA'sı için toast üretir.
/// </summary>
public partial class PasswordManagerViewModel : ObservableObject
{
    private readonly IToastService? _toastService;

    [ObservableProperty]
    private ObservableCollection<PasswordFeatureItem> _features = new();

    [ObservableProperty]
    private ObservableCollection<OnboardingStep> _onboardingSteps = new();

    public PasswordManagerViewModel(IToastService? toastService = null)
    {
        _toastService = toastService;
        LoadData();
    }

    private void LoadData()
    {
        Features = new ObservableCollection<PasswordFeatureItem>
        {
            new("\uE8D7", "Uçtan Uca Şifreleme", "Parolalarınız AES-256 ile şifrelenir; sadece siz erişebilirsiniz."),
            new("\uE8D4", "Parola Üreteci", "Güçlü, benzersiz parolalar tek tıkla üretin."),
            new("\uE8A7", "Oto-Doldur", "Tarayıcı ve uygulamalarda formları otomatik doldurur."),
            new("\uE7BA", "Karanlık Web Taraması", "Parolanız ihlal edildiyse anında uyarı alın."),
            new("\uE89C", "2FA Kodları", "TOTP tabanlı iki adımlı doğrulama kodlarını yönetin."),
            new("\uE70B", "Güvenli Notlar", "Kart bilgileri ve önemli notları şifreli saklayın."),
        };

        OnboardingSteps = new ObservableCollection<OnboardingStep>
        {
            new(1, "Master Parola Oluştur", "Tüm kasanızı koruyacak tek bir güçlü parola."),
            new(2, "Parolaları İçe Aktar", "Tarayıcınızdan veya CSV dosyasından kolayca aktarın."),
            new(3, "Tüm Cihazlarda Kullan", "Windows, Android ve iOS'da senkronize deneyim."),
        };
    }

    [RelayCommand]
    private void StartSetup()
    {
        _toastService?.Info("Parola Yöneticisi", "Kurulum sihirbazı yakında aktif olacak.");
    }

    [RelayCommand]
    private void LearnMore()
    {
        _toastService?.Info("Daha Fazla Bilgi", "Özellik detaylarına yakında bu sayfadan ulaşabileceksiniz.");
    }

    [RelayCommand]
    private void UpgradeToPremium()
    {
        _toastService?.Info("Premium", "Premium plan yakında satın alma akışı üzerinden sunulacak.");
    }
}

/// <summary>
/// PM sayfasındaki özellik kartı.
/// </summary>
public record PasswordFeatureItem(string Glyph, string Title, string Description);

/// <summary>
/// "Nasıl Çalışır?" adımı.
/// </summary>
public record OnboardingStep(int StepNumber, string Title, string Description)
{
    public string StepNumberText => StepNumber.ToString();
}

#pragma warning restore MVVMTK0045
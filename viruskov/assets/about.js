/* VIRUSKOV — story page: bilingual timeline + community, rendered from data */
(function () {
  'use strict';

  var CATS = {
    roots: { tr: 'Temeller', en: 'Roots' },
    birth: { tr: 'Doğuş', en: 'Birth' },
    alliances: { tr: 'İttifak', en: 'Alliances' },
    kernel: { tr: 'Teknik', en: 'Technical' }
  };

  var TIMELINE = [
    {
      cat: 'roots',
      date: { tr: '2019 · Proje öncesi', en: '2019 · Before the project' },
      title: { tr: 'Avast forumunda saldırgan IP raporları', en: 'Reporting attacker IPs on the Avast forum' },
      body: {
        tr: 'Resmi başlangıç 15 Nisan 2023 olsa da siber güvenliğe ilgi çok daha eskiye dayanıyor. Emirhan Uçan, pek çok kavramı yeni keşfederken Avast forumlarında zararlı aktiviteleri ve saldırgan IP adreslerini raporlayarak ilk reflekslerini kazandı.',
        en: 'The official start is 15 April 2023, but the interest in security goes back much further. While still discovering the basics, Emirhan Uçan built his first reflexes by reporting malicious activity and attacker IP addresses on the Avast forums.'
      },
      links: [{ href: 'https://community.avast.com/t/hackers-id-founded-94-74-81-92-80/754120', tr: 'Avast forum kaydı', en: 'Avast forum post' }]
    },
    {
      cat: 'roots',
      date: { tr: 'Ocak 2022 · Öz-gelişim', en: 'January 2022 · Self-study' },
      title: { tr: 'GitHub, bir buçuk yıl satranç ve yapay zekâsız çalışma', en: 'GitHub, eighteen months of chess and no AI tools' },
      body: {
        tr: 'Ocak 2022\'de GitHub\'a katılarak yazılıma başlandı. Yaklaşık bir buçuk yıl boyunca yapay zekâ araçları olmadan çalışıldı. Bu dönemin büyük kısmı satranç oynayarak geçti; analitik düşünmenin temeli satranç tahtasında atıldı.',
        en: 'Joined GitHub in January 2022 and started programming. For about eighteen months, everything was done without AI tools. Most of that period went into chess, which is where the analytical foundation was laid.'
      }
    },
    {
      cat: 'roots',
      date: { tr: 'Mayıs 2022 · İlk program', en: 'May 2022 · First program' },
      title: { tr: 'Satranc.exe ve elle yazılmış test zararlıları', en: 'Satranc.exe and hand-written test malware' },
      body: {
        tr: 'İlk açık program <strong>Satranc.exe</strong> yayınlandı. Depoda satranç kodlarının yanında, savunma reflekslerini test etmek için elle yazılmış virüs simülasyonları da vardı. Zararlının nasıl çalıştığını yazarak öğrenme dönemi başladı.',
        en: 'The first public program, <strong>Satranc.exe</strong>, was released. Alongside the chess code, the repository held hand-written malware simulations used to test defensive reflexes. Learning how malware works by writing it had begun.'
      },
      links: [{ href: 'https://github.com/satrancistanbul/Satranc.exe/tree/main/Dosya', tr: 'Satranc.exe deposu', en: 'Satranc.exe repository' }]
    },
    {
      cat: 'birth', key: true,
      date: { tr: '15 Nisan 2023 · 13:27', en: '15 April 2023 · 13:27' },
      title: { tr: 'Antivirus.sln: ilk başarısız deneme ve pes etmeme kararı', en: 'Antivirus.sln: a failed first attempt, and the decision to keep going' },
      body: {
        tr: 'Antivirüs geliştirme serüveninin resmi doğum tarihi. Visual Studio\'da oluşturulan <strong>Antivirus.sln</strong> deneyimsizlik nedeniyle başarısız oldu; ama bu başarısızlık projeyi bırakmak yerine daha derin öğrenme isteğini doğurdu.',
        en: 'The official birth of the project. <strong>Antivirus.sln</strong>, created in Visual Studio, failed through inexperience. Instead of ending the project, that failure pushed it to dig deeper.'
      },
      links: [{ href: 'https://github.com/Siradankullanici/Antivirus/blob/4ae35cfcc59d8051ecc2fd2037d232aed4d686ab/Antivirus.rar', tr: 'Antivirus.rar ilk arşiv', en: 'Antivirus.rar first archive' }]
    },
    {
      cat: 'birth',
      date: { tr: '7 Mayıs 2023 · Git commit', en: '7 May 2023 · Git commit' },
      title: { tr: 'İlk açık commitler ve temel taramalar', en: 'First public commits and basic scanning' },
      body: {
        tr: 'İlk açık commitler Siradankullanici/Antivirus deposunda atıldı. Başlangıçta basit hash eşleştirmeleri ve dosya uzantısı denetimleri vardı.',
        en: 'The first public commits landed in the Siradankullanici/Antivirus repository: simple hash matching and file-extension checks.'
      },
      links: [{ href: 'https://github.com/Siradankullanici/Antivirus/commit/127eb918236ad9473f7474e4be8f0a0d78800c91', tr: '7 Mayıs 2023 commiti', en: '7 May 2023 commit' }]
    },
    {
      cat: 'birth',
      date: { tr: '10 Mayıs 2023 · 13:05:34', en: '10 May 2023 · 13:05:34' },
      title: { tr: '"I improved code": halka açık geliştirme günlüğü', en: '"I improved code": a public development log' },
      body: {
        tr: 'YouTube\'da paylaşılan video ve 10 Mayıs 2023 tarihli "I improved code" yorumuyla geliştirme süreci kamuya açık biçimde kayıt altına alındı.',
        en: 'A YouTube video and a comment dated 10 May 2023 reading "I improved code" put the development process on public record.'
      },
      links: [{ href: 'https://www.youtube.com/watch?v=VP0zjF83zjc&lc=UgwgMrkyuKvUyujSSmx4AaABAg', tr: 'YouTube kaydı', en: 'YouTube record' }]
    },
    {
      cat: 'birth',
      date: { tr: '11 Mayıs 2023 · Discord', en: '11 May 2023 · Discord' },
      title: { tr: 'blackbanner.exe ile ilk yol arkadaşlığı', en: 'First companion: blackbanner.exe' },
      body: {
        tr: 'Discord\'da tanışılan <strong>blackbanner.exe</strong> ile yazılım ve güvenlik üzerine sohbetler başladı. Projenin ilk günlerindeki bu arkadaşlık, motivasyonu ayakta tuttu.',
        en: 'Conversations about software and security began with <strong>blackbanner.exe</strong>, met on Discord. That friendship kept motivation alive in the earliest days.'
      }
    },
    {
      cat: 'birth', key: true,
      date: { tr: '20 Mayıs 2023 · 13:11–13:29', en: '20 May 2023 · 13:11–13:29' },
      title: { tr: 'Turko Antivirus\'ten Hydra Dragon\'a', en: 'From Turko Antivirus to Hydra Dragon' },
      body: {
        tr: 'Proje ilk başta <strong>Turko Antivirus</strong> olarak anılıyordu. O gün Discord\'da yazılan mesajlar, oyun modlamaktan antivirüs mimarisine geçişin en samimi belgesi. 13:29\'daki mesaj, Comodo mimarisinin o tarihte de bilindiğini ve Hydra Dragon isminin seçildiğini gösteriyor.',
        en: 'The project was first known as <strong>Turko Antivirus</strong>. The Discord messages from that day are the most candid record of the shift from game modding to antivirus architecture. The 13:29 message shows that the Comodo architecture was already familiar, and that the name Hydra Dragon was chosen.'
      },
      quotes: [
        { cite: 'Discord · Hydra [ANY] · 20.05.2023 13:11', tr: 'Ben antivirüse takıntılı kalayım… Antivirüs ismi düşünmek lazım. Hydra Antivirus olabilir. Tulpar Antivirus olabilir.', en: 'I’ll stay obsessed with antivirus… We need a name. Could be Hydra Antivirus. Could be Tulpar Antivirus.' },
        { cite: 'Discord · 20.05.2023 13:29', tr: 'Hydra Dragon nasıl? Gerçi Comodo\'ya benzedi…', en: 'How about Hydra Dragon? Though it sounds a bit like Comodo…' }
      ]
    },
    {
      cat: 'birth',
      date: { tr: '2023 · Açık kaynak iş birliği', en: '2023 · Open-source collaboration' },
      title: { tr: 'Xylent forku ve Rutuj-Runwal', en: 'The Xylent fork and Rutuj-Runwal' },
      body: {
        tr: 'Proje bir aşamada forklanarak <strong>Xylent</strong> adıyla geliştirildi. <strong>Rutuj-Runwal</strong> bu süreçte emeği geçen açık kaynak geliştiricilerden biri oldu.',
        en: 'At one point the project was forked and developed as <strong>Xylent</strong>. <strong>Rutuj-Runwal</strong> was one of the open-source developers who contributed along the way.'
      },
      links: [{ href: 'https://github.com/Rutuj-Runwal/Xylent', tr: 'Xylent deposu', en: 'Xylent repository' }]
    },
    {
      cat: 'alliances',
      date: { tr: '15 Ağustos 2024 · 16:06', en: '15 August 2024 · 16:06' },
      title: { tr: 'Sparrow sunucusu ve Ramiz (Yusif Musayev)', en: 'The Sparrow server and Ramiz (Yusif Musayev)' },
      body: {
        tr: 'Sparrow sunucusundaki bir ban olayının ardından Ramiz\'in DM\'den yazmasıyla uzun soluklu bir dostluk ve geliştirme ortaklığı başladı. Ramiz aracılığıyla Hacımurad ile tanışıldı ve çekirdek ekip pekişti.',
        en: 'After a ban incident on the Sparrow server, Ramiz reached out by DM, and a lasting friendship and development partnership began. Through Ramiz came Hacımurad, and the core group took shape.'
      },
      links: [
        { href: 'https://github.com/elnureisayeva1-cloud', tr: 'Ramiz · GitHub', en: 'Ramiz · GitHub' },
        { href: 'https://github.com/hyron0145', tr: 'Hacımurad · GitHub', en: 'Hacımurad · GitHub' }
      ]
    },
    {
      cat: 'alliances',
      date: { tr: '19 Aralık 2024 · 14:24', en: '19 December 2024 · 14:24' },
      title: { tr: 'Technopat\'tan winball501', en: 'winball501, from Technopat' },
      body: {
        tr: 'Technopat Sosyal\'den tanınan <strong>winball501</strong> ile ilk temas Discord\'da tek bir mesajla kuruldu: "sa nasil gidiyor". Güvenlik topluluğundaki dayanışma böyle büyüdü.',
        en: 'First contact with <strong>winball501</strong>, known from Technopat Sosyal, was a single Discord message: "sa nasil gidiyor" (hey, how’s it going). That is how the circle grew.'
      },
      links: [{ href: 'https://github.com/winball501', tr: 'winball501 · GitHub', en: 'winball501 · GitHub' }]
    },
    {
      cat: 'kernel',
      date: { tr: '2023 – 2024 · Makine öğrenimi', en: '2023 – 2024 · Machine learning' },
      title: { tr: 'Özellik ezberlemeden genellemeye', en: 'From feature memorisation to generalisation' },
      body: {
        tr: 'İlk Python modelleri ONNX ya da soyut skorlama değildi; belirli zararlıların PE özelliklerini ezberleyerek aynı ailenin varyantlarını yakalıyordu. Tespitlerde özel virüs isimlerinin görünmesinin sebebi buydu. Sistem olgunlaştıkça PE başlık sapmalarını ve davranış anomalilerini skorlayan <strong>genelleştirilmiş</strong> modellere geçildi.',
        en: 'The first Python models were neither ONNX nor abstract scorers; they memorised the PE features of specific samples and caught variants of the same family. That is why detections carried specific malware names. As the system matured, it moved to <strong>generalised</strong> models that score PE header deviations and behavioural anomalies.'
      }
    },
    {
      cat: 'kernel', key: true,
      date: { tr: '2024 → 2026 · Mimari dönüşüm', en: '2024 → 2026 · Architecture shift' },
      title: { tr: '"Kernele önem ver": Owlyshield, Sanctum ve OpenEDR', en: '"Focus on the kernel": Owlyshield, Sanctum and OpenEDR' },
      body: {
        tr: 'Çekirdek seviyesinde çalışan zararlılar artınca <strong>OmniDefender</strong> geliştiricisinin "kernele önem ver" tavsiyesi kırılma noktası oldu. Usermode sınırları aşılıp Ring-0\'a geçildi: önce Owlyshield derlenip projeye katıldı, ardından Sanctum ve OpenEDR derlenebilir hale getirilerek kurumsal düzeyde bir EDR çekirdeği kuruldu.',
        en: 'As kernel-level malware became more common, advice from the <strong>OmniDefender</strong> developer ("focus on the kernel") became the turning point. The project moved past usermode limits into Ring-0: Owlyshield was built and integrated first, then Sanctum and OpenEDR were made buildable, forming an enterprise-grade EDR core.'
      },
      links: [
        { href: 'https://github.com/HydraDragonAntivirus/HydraDragonAntivirus', tr: 'Ana EDR deposu', en: 'Main EDR repository' },
        { href: 'https://github.com/Xacone/BestEdrOfTheMarket', tr: 'BestEdrOfTheMarket', en: 'BestEdrOfTheMarket' }
      ]
    },
    {
      cat: 'alliances',
      date: { tr: 'Altyapı · İlk web adımı', en: 'Infrastructure · First web attempt' },
      title: { tr: 'Emrah Demirci: .agents mimarisi ve Docker', en: 'Emrah Demirci: the .agents structure and Docker' },
      body: {
        tr: 'Proje ajan altyapısına evrilirken <strong>Emrah Demirci</strong> depodaki <code>.agents</code> klasör mimarisini kurdu. İlk web sitesi denemesini de Docker konteynerleri üzerinden Emirhan ile birlikte yaptı; bu deneme resmi sitenin temelini attı.',
        en: 'As the project grew into agent-based infrastructure, <strong>Emrah Demirci</strong> set up the repository’s <code>.agents</code> structure. He also ran the first website attempt with Emirhan using Docker containers, laying the groundwork for the official site.'
      },
      links: [{ href: 'https://github.com/emrahd0732', tr: 'Emrah Demirci · GitHub', en: 'Emrah Demirci · GitHub' }]
    },
    {
      cat: 'alliances', key: true,
      date: { tr: '2026 · viruskov.com', en: '2026 · viruskov.com' },
      title: { tr: 'Benan\'ın desteğiyle viruskov.com ve Caymaz', en: 'viruskov.com with Benan’s help, and Caymaz' },
      body: {
        tr: 'Yazılım Mekanı topluluğundan <strong>Benan</strong>\'ın doğrudan teknik ve altyapı desteğiyle viruskov.com 2026\'da yayına girdi. Yine Yazılım Mekanı\'ndan <strong>Caymaz</strong> (Yusuf Caymaz), açık kaynak <strong>DefenderUI</strong> arayüz aracıyla topluluğun parçası oldu (ticari defenderui.com ile ilgisi yoktur). Hydra Dragon vizyonu, VIRUSKOV kimliğiyle dünyaya açıldı.',
        en: 'With direct technical and infrastructure support from <strong>Benan</strong> of the Yazılım Mekanı community, viruskov.com went live in 2026. <strong>Caymaz</strong> (Yusuf Caymaz), also from Yazılım Mekanı, joined with his open-source <strong>DefenderUI</strong> front-end (unrelated to the commercial defenderui.com). The Hydra Dragon vision now faces the world as VIRUSKOV.'
      },
      links: [
        { href: 'https://github.com/caymazyusuf72/defenderui', tr: 'DefenderUI deposu', en: 'DefenderUI repository' },
        { href: 'https://github.com/caymazyusuf72', tr: 'Caymaz · GitHub', en: 'Caymaz · GitHub' }
      ]
    }
  ];

  var PEOPLE = [
    {
      name: 'Emirhan Uçan', lead: true,
      role: { tr: 'Kurucu · proje lideri', en: 'Founder · project lead' },
      body: {
        tr: '15 Nisan 2023\'ten bu yana zararlı analizi, tersine mühendislik, kernel sürücüleri ve ML mimarisini yürütüyor. Discord: hydra_dragon_antivirus',
        en: 'Has led malware analysis, reverse engineering, kernel drivers and the ML architecture since 15 April 2023. Discord: hydra_dragon_antivirus'
      },
      links: [{ href: 'https://github.com/HydraDragonAntivirus/HydraDragonAntivirus', tr: 'Depo', en: 'Repository' }]
    },
    {
      name: 'Ramiz (Yusif Musayev)',
      role: { tr: 'Çekirdek ittifak', en: 'Core ally' },
      body: { tr: '15 Ağustos 2024\'ten bu yana projeye maddi ve manevi desteğini esirgemeyen geliştirme ortağı.', en: 'Development partner who has backed the project, materially and morally, since 15 August 2024.' },
      links: [{ href: 'https://github.com/elnureisayeva1-cloud', tr: 'GitHub', en: 'GitHub' }]
    },
    {
      name: 'Hacımurad',
      role: { tr: 'Dost · destek', en: 'Friend · support' },
      body: { tr: 'Ramiz aracılığıyla tanışılan; projenin büyümesinde ve motivasyonun korunmasında hep yanında olan dost.', en: 'Met through Ramiz; a constant presence in keeping the project growing and motivated.' },
      links: [{ href: 'https://github.com/hyron0145', tr: 'GitHub', en: 'GitHub' }]
    },
    {
      name: 'Rutuj-Runwal',
      role: { tr: 'Katkıda bulunan', en: 'Contributor' },
      body: { tr: 'Xylent döneminde açık kaynak çekirdeğin genişletilmesinde rol oynayan geliştirici.', en: 'Developer who helped extend the open-source core during the Xylent era.' },
      links: [{ href: 'https://github.com/Rutuj-Runwal/Xylent', tr: 'Xylent', en: 'Xylent' }]
    },
    {
      name: 'winball501',
      role: { tr: 'Technopat · topluluk', en: 'Technopat · community' },
      body: { tr: '19 Aralık 2024\'te "sa nasil gidiyor" ile başlayan dostlukla projenin yanında duran geliştirici.', en: 'Developer who has stood by the project since a "sa nasil gidiyor" on 19 December 2024.' },
      links: [{ href: 'https://github.com/winball501', tr: 'GitHub', en: 'GitHub' }]
    },
    {
      name: 'Emrah Demirci',
      role: { tr: 'Agents · Docker', en: 'Agents · Docker' },
      body: { tr: 'Depodaki .agents yapısını kuran ve ilk web denemesini Docker üzerinde birlikte yapan mimar.', en: 'Built the repository’s .agents structure and ran the first web attempt on Docker together with Emirhan.' },
      links: [{ href: 'https://github.com/emrahd0732', tr: 'GitHub', en: 'GitHub' }]
    },
    {
      name: 'Caymaz (Yusuf Caymaz)',
      role: { tr: 'DefenderUI geliştiricisi', en: 'DefenderUI developer' },
      body: { tr: 'Yazılım Mekanı\'ndan; açık kaynak DefenderUI arayüz aracının geliştiricisi. Ticari defenderui.com ile ilgisi yoktur.', en: 'From Yazılım Mekanı; developer of the open-source DefenderUI front-end. Unrelated to the commercial defenderui.com.' },
      links: [
        { href: 'https://github.com/caymazyusuf72/defenderui', tr: 'DefenderUI', en: 'DefenderUI' },
        { href: 'https://github.com/caymazyusuf72', tr: 'GitHub', en: 'GitHub' }
      ]
    },
    {
      name: 'Benan',
      role: { tr: 'Web altyapısı', en: 'Web infrastructure' },
      body: { tr: 'viruskov.com\'u 2026\'da teknik ve altyapı desteğiyle hayata geçiren dost.', en: 'Brought viruskov.com to life in 2026 with technical and infrastructure support.' }
    },
    {
      name: 'blackbanner.exe',
      role: { tr: 'İlk yol arkadaşı', en: 'Earliest companion' },
      body: { tr: '11 Mayıs 2023\'ten itibaren Discord\'da fikir ve sohbet paylaşılan ilk arkadaş.', en: 'The first friend to share ideas and late-night conversations on Discord, from 11 May 2023.' }
    }
  ];

  var lang = function () { return window.ViruskovI18n ? window.ViruskovI18n.getLang() : 'tr'; };
  var esc = function (s) {
    return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; });
  };
  var state = { filter: 'all', q: '' };

  function linksHtml(links, L) {
    if (!links || !links.length) return '';
    return '<div class="a-links">' + links.map(function (l) {
      return '<a href="' + esc(l.href) + '" target="_blank" rel="noopener">' + esc(l[L]) + '</a>';
    }).join('') + '</div>';
  }

  function plain(html) { return String(html).replace(/<[^>]+>/g, ' '); }

  function renderTimeline() {
    var L = lang();
    var list = document.getElementById('timelineList');
    if (!list) return;
    var q = state.q.toLowerCase();
    var counts = { all: 0, roots: 0, birth: 0, alliances: 0, kernel: 0 };
    var html = '';
    TIMELINE.forEach(function (e) {
      var text = [e.date[L], e.title[L], plain(e.body[L]), (e.quotes || []).map(function (x) { return x[L] + ' ' + x.cite; }).join(' '),
        (e.links || []).map(function (x) { return x[L]; }).join(' ')].join(' ').toLowerCase();
      var matchQ = !q || text.indexOf(q) !== -1;
      if (matchQ) { counts.all++; counts[e.cat]++; }
      if (!matchQ || (state.filter !== 'all' && e.cat !== state.filter)) return;
      html += '<li class="a-item' + (e.key ? ' is-key' : '') + '">' +
        '<div class="a-date"><span>' + esc(e.date[L]) + '</span><span class="a-cat">' + esc(CATS[e.cat][L]) + '</span></div>' +
        '<h3>' + esc(e.title[L]) + '</h3>' +
        '<p>' + e.body[L] + '</p>' +
        (e.quotes || []).map(function (x) {
          return '<blockquote class="a-quote"><cite>' + esc(x.cite) + '</cite><q>' + esc(x[L]) + '</q></blockquote>';
        }).join('') +
        linksHtml(e.links, L) + '</li>';
    });
    list.innerHTML = html || '<li class="a-empty">' + (L === 'tr' ? 'Eşleşen kayıt yok.' : 'No matching entries.') + '</li>';
    Object.keys(counts).forEach(function (k) {
      var el = document.getElementById('cnt-' + k);
      if (el) el.textContent = counts[k];
    });
  }

  function initials(name) {
    var parts = name.replace(/\(.*\)/, '').trim().split(/[\s.\-]+/).filter(Boolean);
    return ((parts[0] || '')[0] + ((parts[1] || '')[0] || '')).toUpperCase();
  }

  function renderPeople() {
    var L = lang();
    var grid = document.getElementById('peopleGrid');
    if (!grid) return;
    grid.innerHTML = PEOPLE.map(function (p) {
      return '<article class="a-person' + (p.lead ? ' is-lead' : '') + '">' +
        '<div class="a-person-top"><span class="a-avatar" aria-hidden="true">' + esc(initials(p.name)) + '</span>' +
        '<div><h3>' + esc(p.name) + '</h3><span class="a-role">' + esc(p.role[L]) + '</span></div></div>' +
        '<p>' + esc(p.body[L]) + '</p>' + linksHtml(p.links, L) + '</article>';
    }).join('');
  }

  function init() {
    renderTimeline();
    renderPeople();
    document.querySelectorAll('.a-filter').forEach(function (btn) {
      btn.addEventListener('click', function () {
        document.querySelectorAll('.a-filter').forEach(function (b) { b.classList.remove('is-active'); });
        btn.classList.add('is-active');
        state.filter = btn.getAttribute('data-filter');
        renderTimeline();
      });
    });
    var s = document.getElementById('tlSearch');
    if (s) s.addEventListener('input', function () { state.q = s.value.trim(); renderTimeline(); });
    window.addEventListener('viruskov_lang_changed', function () { renderTimeline(); renderPeople(); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

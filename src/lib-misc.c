/*
 *  Copyright 2016 Mario Di Raimondo <diraimondo@dmi.unict.it>
 *
 *  This source code is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This source code is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * libreria di supporto con varie funzioni:
 * - estrazione seed random dal pool di sistema per i sistemi Linux, Mac OS X e
 *   Windows;
 * - selezione della dimensione di un gruppo finito affinché questo sia sicuro
 *   contro attacchi al logaritmo discreto utilizzando algoritmi non-generici
 *   (raccomandazioni NIST)
 * - selezione curva/pairing per la libreria PBC secondo il livello di sicurezza
 *   (raccomandazioni NIST)
 */

#include "lib-misc.h"

#define dev_random "/dev/random"

/* estrae un seed sicuro, di lunghezza indicata, dall'interfaccia offerta dal
 * sistema operativo */
int extract_randseed_os_rng(uint8_t *seed, size_t seed_bits) {
    assert(seed);
    assert(seed_bits > 0);
    long seed_bytes = (size_t)ceil(seed_bits / 8.0);
    assert(seed_bytes > 0);

#if defined(_WIN32) || defined(__CYGWIN__)
    HCRYPTPROV h_provider;

    if (!CryptAcquireContext(&h_provider, 0, 0, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptGenRandom(h_provider, seed_bytes, (BYTE *)seed)) {
        CryptReleaseContext(h_provider, 0);
        return -1;
    }
#else
    int fd;

    if ((fd = open(dev_random, O_RDONLY)) == -1)
        return -1;
    for (long i = 0; i < seed_bytes; i++)
        if (read(fd, seed + i, sizeof(char)) == -1) {
            close(fd);
            return -1;
        }
#endif /* defined(_WIN32) || defined(__CYGWIN__) */

#if defined(_WIN32) || defined(__CYGWIN__)
    CryptReleaseContext(h_provider, 0);
#else
    close(fd);
#endif /* defined(_WIN32) || defined(__CYGWIN__) */

    return 0;
}

/* alimenta lo stato del PRNG specificato con un seed, di lunghezza indicata,
   estratto dall'interfaccia offerta dal sistema operativo */
int gmp_randseed_os_rng(gmp_randstate_t state, size_t bits) {

    assert(state);
    assert(bits > 0);
    long seed_bytes = (size_t)ceil(bits / 8.0);
    assert(seed_bytes > 0);

    mpz_t seed;
    uint8_t buffer[seed_bytes];

    if (extract_randseed_os_rng(buffer, bits) < 0)
        return -1;

    mpz_init(seed);
    mpz_import(seed, seed_bytes, -1, sizeof(char), 0, 0, buffer);
    gmp_randseed(state, seed);

    mpz_clear(seed);
    return 0;
}

/* seleziona la dimensione di un gruppo finito affinché questo sia sicuro
   contro attacchi al logaritmo discreto utilizzando algoritmi non-generici
   (raccomandazioni NIST) */
unsigned int
non_generic_dlog_secure_size_by_security_level(unsigned int level) {
    /* raccomandazioni NIST (2020) */
    if (level <= 80)
        return 1024;
    else if (level <= 112)
        return 2048;
    else if (level <= 128)
        return 3072;
    else if (level <= 192)
        return 7680;
    else
        return 15360;
}
/* c'è anche la macro: generic_dlog_secure_size_by_security_level(level) */

#if defined(PBC_SUPPORT)
int _pairing_type_d_callback_function(pbc_cm_t cm, void *data) {
    pbc_param_init_d_gen((pbc_param_ptr)data, cm);
    return 1;
}

int _pairing_type_g_callback_function(pbc_cm_t cm, void *data) {
    pbc_param_init_g_gen((pbc_param_ptr)data, cm);
    return 1;
}

/* seleziona curva/pairing per la libreria PBC secondo il livello di sicurezza
   (raccomandazioni NIST) */
void select_pbc_param_by_security_level(pbc_param_t param,
                                        pbc_pairing_type_t type,
                                        unsigned int level, void *aux) {
    unsigned int generic_dlog_secure_size, non_generic_dlog_secure_size;

    assert((type >= pbc_pairing_type_a) && (type <= pbc_pairing_type_i));
    assert(level > 16);

    /* raccomandazioni NIST (2020) */
    generic_dlog_secure_size = generic_dlog_secure_size_by_security_level(level);
    non_generic_dlog_secure_size =
        non_generic_dlog_secure_size_by_security_level(level);

    switch (type) {
    case pbc_pairing_type_a:
        /* Curve SS (Super-Singolari): embedding degree = 2 */
        pbc_param_init_a_gen(param, generic_dlog_secure_size,
                             non_generic_dlog_secure_size / 2);
        break;
    case pbc_pairing_type_a1:
        /* Curve SSc (Super-Singolari di ordine dato/composito)*/
        pbc_param_init_a1_gen(param, (mpz_ptr)aux);
        break;
    case pbc_pairing_type_d: {
        /* Curve MNT (Miyaji-Nakabayashi-Takano): embedding degree = 6 */

        /* selezione tramite discriminanti noti (lento)
           o tramite parametri diretti (se disponibili): */
        int discriminant = 0;
        if (level <= 80) {
            discriminant = 277699; // q=175 r=167
        } else if (level <= 112) {
            // discriminant = 519243; // q=248 r=224 NB: scartato: su GT il DLog
            // è debole: (248x6)=1488 << 2048
            // discriminant = 476971; // q=347 r=332
            int r = pbc_param_init_set_str(param, "type d\
            q 249725319727730919700475045591545787682903507888220731395958908303279371164545357221522547172731812116737\
            n 249725319727730919700475045591545787682903507888220747198658669031853046854762545484961208827864952908881\
            h 51541\
            r 4845178008337651960584293001523947685976281172042078097022926777358860845826866872683130106669737741\
            a 205479676210407588842844395281558408760747629658751508010018530940016620749851098837439726302275941085737\
            b 142912764747743925755460608419719460220698529411089249747487003425544624002767311038406216455582597135336\
            k 6\
            nk 242535584663234070311274653505055491002480829760282076568885078403090573799048889531604691902917202150159242077646320887757837851695744694034088415050415576671618051539166792816455969134925647422299126102439382860704494378716484002167539069394575215781136869457466522465313196572791804438622104663532515615076010799724861531318739519787114916020598884052411300610762389988181573484110749207838771822414652174675926338859528358392513080135410771757961198047534924954265431039425575283602076418063628052095664675131331409305104659956675697181624775669435281362517139411681291771868286960884224448963717259684410245843410820213760\
            hk 10331324254211998279180554424513794447840337639749388253135901177752220889564639690924134154612976712953818029710078770498180896017570340090033046627300002811462365766412735865813293864289544687143691162201428408833246805494438536225426008262992582139747979988332020005737984330479158713896984797154473267924033165551652814770833906625846176149565957919467927764526760216464741545691755875899964904282279304666011994736190376960\
            coeff0 180473114504396410267168303713114858425552375705216620680319384920891420913548656975426597145079700221942\
            coeff1 108932518796128656403426106167109562165645136549649068359711602652566230420540742382133287435412773285862\
            coeff2 223453750434935832526340182442577752002088701403249531976902972431624165964731236524743060367192438387353\
            nqr 244963173507266938235539383443602512137290519396344466970811861754786069712885850118391142918884286378163");
            assert(r == 0);
            return;
        } else if (level <= 128) {
            // discriminant = 2571363; // q=311 r=289 NB: scartato: su GT il
            // DLog è debole: (311*6)=1866 << 3072
            // discriminant = 311387; // q=522 r=514
            int r = pbc_param_init_set_str(param, "type d\
            q 8119928374079253991185425926153258050977083573846617974041124280957494110686649403117001928185790126899721270225933747411506777383757461377406125687426801937\
            n 8119928374079253991185425926153258050977083573846617974041124280957494110686652252665803770199162172399111096226930470181125756139260957556757669128734451893\
            h 201\
            r 40397653602384348214852865304245064930234246636052825741498130751032309008391304739630864528354040658702045254860350597916048538006273420680386413575793293\
            a 194291271993062349337069629037827066459850665964217569611936488102642062532007926390480563694039734880837040244590865852187073569942451922656633596088439906\
            b 5542813097381544227014997036794056744957956159873890362435373846040090782145771553004988327919886574520372206980349742175795900635799942200041839522343494562\
            k 6\
            nk 286624420757452846547558592832616869656283939240260537419068534839356918415830784868522168268786772079423808689001962780393433348955025909417567681361729799442986515677684225398933753371340614624107124032571672397531412488938538167285468013854161792364109308742820830797767795795330376157496705933518223105692940847279700333811121067268966492159622547606615345605981769371637709185647063822387112314813555893132651180185523136161536288781129245463349304480122820767378455708758075160019130646238606251724310209580447179968928987434276353666446051254743451570657039114873335324473051407987787553063366187396885036547073580884953789266172119240387401053054946314057409497966308720447492248157818330586773437826623052817794792957208611954437923714947966810834207931332048132321027037813303362268796049914380175583620527064492679959499492502217590391028812907430562255457753649212536147686258969756380636130847254470248364644005408070285530977216\
            hk 175630892475624722029922200934415512359104475739233334371977206507220809428247624320766256197617775327580483637697696705131017285779786328447303470129119833897812829959165929795020231939496884075153334937765270009534492854122884444264779586877345633080497422871675916170831657432180524496689676387720542015569427301850319459123180343763247038236957415590603967826189877568259892488880698012258908670943353374482488012348470119242023456958887102986493706114092802287874952885856638535585706440106189629665730766337767905914249043732651160429881452853481009544157461597483158233908106308242221606613751058530657019439061633366074101184\
            coeff0 183270755204793316270973615121035418180272181855342374850628993569419333885164800946938665688870977259052429463162713137237415747221909951531159781670224193\
            coeff1 4420012455684356829141084618253895369665508266734431382359973215745213718161384405241613151451262109760093436528224361138425550109350897322624068199842430549\
            coeff2 3549997967747217887205475789788641988268970614616166759164310210564001720421074521811369039373155743849290380010316278955494511717982026644041982947095020083\
            nqr 5604379921766334530881484112875305450465392023664879178190451853254214902967795509774097034685746943497436675589223058860619716350787995577996572786003998092");
            assert(r == 0);
            return;
        } else if (level <= 192)
            discriminant = 0;
        else
            discriminant = 0;

        assert((discriminant > 0) &&
               (((discriminant % 4) == 0) || ((discriminant % 4) == 3)));
        int r = pbc_cm_search_d(_pairing_type_d_callback_function, param,
                                discriminant, generic_dlog_secure_size + 1);
        assert(r != 0);
        /* param è impostato dalla funzione di callback */
    }; break;
    case pbc_pairing_type_e:
        pbc_param_init_e_gen(param, generic_dlog_secure_size,
                             non_generic_dlog_secure_size);
        break;
    case pbc_pairing_type_f:
        /* Curve BN (Barreto-Naehrig): embedding degree = 12 */
        pbc_param_init_f_gen(param, ((non_generic_dlog_secure_size / 12) <=
                                             generic_dlog_secure_size
                                         ? generic_dlog_secure_size
                                         : non_generic_dlog_secure_size / 12));
        break;
    case pbc_pairing_type_g: {
        /* Curve di Freeman: embedding degree = 10 */

        /* selezione tramite discriminanti noti (LENTO)
           o tramite parametri diretti (se disponibili): */
        int discriminant = 0;
        if (level <= 80) {
            // discriminant = 1666603; // q=149 r=149
            int r = pbc_param_init_set_str(param, "type g \
                q 503189899097385532598615948567975432740967203\
                n 503189899097385532598571084778608176410973351\
                h 1\
                r 503189899097385532598571084778608176410973351\
                a 253298916143596820047248620099220708453763464\
                b 486218285977384292559269245449892777543626173\
                nk 1040684643531490707494989587381629956832530311976146077888095795458709511789670022388326295177424065807612879371896982185473788988016190582073591316127396374860265835641044035656044524481121528846249501655527462202999638159773731830375673076317719519977183373353791119388388468745670818193868532404392452816602538968163226713846951514831917487400267590451867746120591750902040267826351982737642689423713163967384383105678367875981348397359466338807\
                hk 4110127713690841149713310614420858884651261781185442551927080083178682965171097172366598236129731931693425629387502221804555636704708008882811353539555915064049685663790355716130262332064327767695339422323460458479884756000782939428852120522712008037615051139080628734566850259704397643028017435446110322024094259858170303605703280329322675124728639532674407\
                coeff0 27775627449294900086467163084147927356260956\
                coeff1 181955473644686069199241435175159527108912043\
                coeff2 377375703088829372302210292222335415900101118\
                coeff3 343978131119695393117949203446469085565973637\
                coeff4 276516399170985053319078354072508042780594285\
                nqr 406500356245222891204862603877753845883181622");
            assert(r == 0);
            return;
        } else if (level <= 112) {
            // discriminant = 4543003; // q=231 r=220
            int r = pbc_param_init_set_str(param, "type g\
            q 2729965301220268775324155006899579152624711673059392691757592664443483\
            n 2729965301220268775324155006899579048126571953344405311422728673598901\
            h 3131\
            r 871914819936208487807139893612130005789387401259790901125112958671\
            a 2521889098130356395871134830776744850968481533680554344924664869169089\
            b 1838561875046597514715999437616817564268915989812928977381689215874283\
            nk 22991709867733925180218112054049355166724677832614326391370476633248357811029088797117077746168974890705308714124753179328663604600687191431920901502144820472182847824344833055745819993208449370861015952975497857953835712757922196657330736576450824290314567470899239681275299098878549996044943781225800295208347444014103752594750014086905713537909177042091950754406166690100728248315312973796680543298134791553274862737651363274867172087494343174111673607312100610769713143878804087948358610242597457554714413504920864717154714729566080087931117897208809469495749726670862113894439268735463417455271478479181609819939135895645510398356392660221510576351958575731044609229090306376827342240705007\
            hk 30242880373730346056269896421938319052432507266159873543230912365174073362675765492624547132164278581697932238081234483067671465558566869252493700427954012589053551470009022971834665982504201964968344426473973241129384090507950254970459784884200415824894792092867358899040637297912522156546831443966627053205109019052787240784935916173944181579418419432654610815643187072690630468332337594813748917078733666252107585425869205829795708504842538394407893043726452348813177502604242000727815265232953412603475742969233046727917476816165491285297074113409519721416527\
            coeff0 1506034757609275175743895093502214347946037832864702462816615836301855\
            coeff1 1968048311032386805400715044701652660560531293736055217672441944865008\
            coeff2 147114903074660743829786919871970589322942690329234195256355609615904\
            coeff3 1244387562370713036015712739899649965562710203553754501333280685426521\
            coeff4 2452411591352386055443174334416949464654643533383661731752025726026678\
            nqr 2074735224075027951149830875709496958201021082523693876742983789505905");
            assert(r == 0);
            return;
        } else if (level <= 128) {
            // discriminant = 35707; // q=301  r=279
            int r = pbc_param_init_set_str(param, "type g\
            q 2926412733580100992307561873039833220827733137936969076285307797490604260428897294595498283\
            n 2926412733580100992307561873039833220827733134515616867827312169666529695426765736872221251\
            h 5110691\
            r 572606078821846398521757991833165656234691773483393315664616031308981446036703400161\
            a 1339968299916790916926653666221146380367119411972025628351891869199912881330108258614272576\
            b 2844254022331261272822810359507319734129901699939329803091466444460344761172670368806513906\
            nk 46063377512748482537089618003577254242558445695007443434273557550033488525388363516325927837588331009166167150012128816277692379436390877242533494941843511448813431489678873196016041940043208015092876854937065915614101557007218062769109210182034374445924299210982380550803971738642134399117787960331843503447664931665708073261001200845988004079414374509886169567187422069238774436212534783857793542067544871853185031671098907916829604808413055196383655805759257260061437193407860137537840219704617078159913334192882757123990497312830060919465259966440770722219233626516291512028472448537114407212648955354696534396801085202579041109460887251817225945802094642588661665258426717956574595396604803066331394664465689571207351379574747139364998328697639633050305426401058730671462691067717942594591028469151839170203657077888466429455621978919489055348250808921538717790237401415146062230125915743064395769007\
            hk 140489501090498387310733015339334018305882727380448168334329581652391862717488754811957612287061015032895125876421123271451445499909113334083651941061499193742028737413693545590709609093265950246868482985725180952682619131361801675458679696820416720781103352312148596685060949846861748361625854894265656197712429160322857232088435047773190937166696173542576433797910493618445207592913731950258042598154594431271767089916786911214832147952556811109701426740399311379560628958495599155696260346338539315738917274348993515926512083170188505647153669528702936539372841715301100389831557841925774185191602831094781222256174528065656801367007183624681519345865911010486303344812302240740663118598421049568246263167389620823088693705670581536367\
            coeff0 826259398802167731082743272436075515279782656423981351096023780983064170193615229910999241\
            coeff1 1884866450827360590655634122683032458724395022074338956640466178401463000915337741440045940\
            coeff2 2063601323231654594443244700069871500758329815531486652741662486612486686361303686975084763\
            coeff3 2444667724804546176644946619467818166505913452815647008953191521521745669002634042771826738\
            coeff4 2523993882391765473378658713962982611636142997483221053152401658982457852754875186709328463\
            nqr 2723673016248314021528421180426075652790777832101902808425522706055238938106416730876895102");
            assert(r == 0);
            return;
        } else if (level <= 192)
            discriminant = 0;
        else
            discriminant = 0;

        assert((discriminant > 0) &&
               (((discriminant % 120) == 43) || ((discriminant % 120) == 67)));
        int r = pbc_cm_search_g(_pairing_type_g_callback_function, param,
                                discriminant, generic_dlog_secure_size + 1);
        assert(r != 0);
        /* param è impostato dalla funzione di callback */
    }; break;
    case pbc_pairing_type_i:
        assert(0);
        /* TODO */
        break;
    }
}
#else
#define select_pbc_param_by_security_level(param, type, level, aux) ((void)0)
#endif /* PBC_SUPPORT */

import random
import hashlib
import gmpy2
from gmpy2 import mpz, powmod, invert, mul, add
from Crypto.Util.number import getPrime
import time
import json
import base64
from pymongo import MongoClient
import os
from bson.objectid import ObjectId
import tracemalloc
import time

# Use environment variable for Mongo URI
MONGO_URI = os.getenv("MONGO_URI", "mongodb://192.168.0.61:27017/")
client = MongoClient(MONGO_URI)
db = client["encryption_db"]
ciphertext_collection = db["cpabe_ciphertexts"]

class CPABEOptimized:
    """Optimized CP-ABE with precomputation and lookup tables"""
    
    def __init__(self):
        self.hash_cache = {}
        self.inverse_cache = {}
        self.power_cache = {}
        self.precomputed_values = {}
    
    def hash_to_zp(self, attr, p):
        """Enhanced hash function with caching and guaranteed coprimality"""
        cache_key = (attr, int(p))
        if cache_key in self.hash_cache:
            return self.hash_cache[cache_key]
        
        # Use Blake2b for faster hashing (when available)
        try:
            hash_obj = hashlib.blake2b(attr.encode(), digest_size=32)
        except:
            hash_obj = hashlib.sha256(attr.encode())
        
        p = mpz(p)
        p_minus_1 = p - 1
        
        # Generate hash value in range [1, p-1]
        hash_val = mpz(int(hash_obj.hexdigest(), 16)) % (p_minus_1 - 1) + 2
        
        # Ensure coprimality with p-1 (required for modular inverse to exist) 
        max_attempts = 100  # Increased attempts
        attempts = 0
        
        while gmpy2.gcd(hash_val, p_minus_1) != 1 and attempts < max_attempts:
            hash_val = hash_val + 1
            if hash_val >= p_minus_1:
                hash_val = 2  # Wrap around but stay > 1
            attempts += 1
        
        # Final safety check
        if gmpy2.gcd(hash_val, p_minus_1) != 1:
            # Fallback to a known coprime value
            hash_val = mpz(2)
            while gmpy2.gcd(hash_val, p_minus_1) != 1:
                hash_val += 1
        
        self.hash_cache[cache_key] = hash_val
        return hash_val
    
    def cached_invert(self, a, m):
        """Cached modular inversion with error handling"""
        cache_key = (int(a), int(m))
        if cache_key in self.inverse_cache:
            return self.inverse_cache[cache_key]
        
        a_mpz = mpz(a)
        m_mpz = mpz(m)
        
        # Check if inverse exists before attempting computation
        if gmpy2.gcd(a_mpz, m_mpz) != 1:
            raise ValueError(f"No modular inverse exists for {a} mod {m} (gcd = {gmpy2.gcd(a_mpz, m_mpz)})")
        
        try:
            result = invert(a_mpz, m_mpz)
            self.inverse_cache[cache_key] = result
            return result
        except ZeroDivisionError:
            raise ValueError(f"Failed to compute modular inverse of {a} mod {m}")
    
    def batch_powmod(self, bases, exponents, modulus):
        """Optimized batch modular exponentiation"""
        results = {}
        modulus = mpz(modulus)
        
        # Group by exponent for potential optimization
        exp_groups = {}
        for base, exp in zip(bases, exponents):
            exp_key = int(exp)
            if exp_key not in exp_groups:
                exp_groups[exp_key] = []
            exp_groups[exp_key].append(base)
        
        # Compute powers for each group
        for exp, base_list in exp_groups.items():
            exp_mpz = mpz(exp)
            for base in base_list:
                base_mpz = mpz(base)
                cache_key = (int(base_mpz), int(exp_mpz), int(modulus))
                
                if cache_key in self.power_cache:
                    results[base] = self.power_cache[cache_key]
                else:
                    result = powmod(base_mpz, exp_mpz, modulus)
                    self.power_cache[cache_key] = result
                    results[base] = result
        
        return results
    
    def setup(self):
        """Optimized setup with precomputation tables"""
        start = time.perf_counter()

        p = mpz(4464270263374726220383382728005838210553525937701928444691995439752736524183894075764150447600404916226547098502385524310781809859834986817084694262120212253753083378137579168884399455000035748853155752858594463321727679405089978526783142124281603356922419365345530904256180126238643295967950629946111060271492125827291683009104517254567126504400553409342228697784910268301556218130430987911074131949421163567621926305782291022883323373394442363177320868204438080510764422927448758432564430631786334618035373363895460505316538137899852077930000600716681037715870111610292387303929637649189715495957320069660754017381546374296101287529016857192768211736017137061000485429959909197471200905308312248175234516171184789554969844956659847608119974037666711326803651096763442983672511939653657883906901189765689237461772262063610998074306419033430329320233738749819932569740847335856983635064938959290479692602070857623189113282176041945698150432315127253812501433609791027492795547126634422910606212415460331723420656170395740216762337264231925264410071594193115133825461060581812024620190319101353580072396399986660259027743895025450970122392358298068966363389593699916926193941820268931875972917525299425471341251949440298904599212329245518484769549060773589175560431621995797754868950065138675591807118906710568285965520478015787836747946719243625359445545361766703392598613338273588173158783108134237166157575960836173679394160406262343384913744244005347801676853328583843678192846919199769496593118614031961624239855637145315794564668400055972276654471112964553474854894556994549883542565920125984411705985705601243328477530223946320198751488765459847383233677662349222637050667079411929939868945113490799132642269000655761665249079079127079829235834541032260937648607244038487695987384959914718532961325715690670374651108426075088995437878368930276558623519039525771744661980742023909612637600887983838681029669460402255839055675205501458744687919888270504450398791590004292806238551814307897636603419506217062259834218097367403200757299080555112691287883500185096688090778578057195316598474017510145994492950867343890223985198640796466622214713255114355159)
        
        print(len(p))
        p_minus_1 = p - 1
        
        print(f"Prime generation: {(time.perf_counter() - start)*1000:.0f}ms")
        
        param_start = time.perf_counter()
        
        # Use fixed small generator for consistency and speed
        g = mpz(2)
        
        # Read alpha and beta from files
        alpha = mpz(1658716810567642877415861939443288374313735110388637745839056228966178752719625728909926871023112859101322934012143558759951157748475040036643727427203534080722080578091500943707157153811032735609098508440053641783795957721127013844020793790268583057743370044987199189980530225324334050732369667060877507531853166763941801258213860389945703365371891528556713264127931392482948289598263898218163697800656407503939305867962568200812525532000824722490964452977311105323073216415216397946948279670494939635438370553324800275011012589228291509878350905044571050398968160119608407522231777070427450064499314361852157944618233832331939671005211514314524601015872676437565328760070910758954850234640350243211320150851351444072038502646145679377109842596354289526000409576165976333340325055641781652500483916610166408180892077964994624116347173461791952207177791036614360326266615173897390134937838941284742641067620780104988484030708022086718368452488355038511870342364123432255721248592177907776072603613531945546275468340782304488397997076723845668660863422738953166337913658430599056742423951131993305616707358600493773087462538856897820556829105515752625639279374913301435246407977012634825537430657854578228522321324637131168234433475342547126992175574189699756287139631474355189405436888445889479101357291859689970871566515675218672462648231662978375364067373573357800042337127891968563497578789445336632396037163177701285665769842207033166977361503187646623786817561755021537500933658537567348048976038587425044438708539188655432369015215864162538588635008036567346363853878573662651200372149701341024564415983234385279732427470837772067343782282833673110552451807691752698433738437341342632400663633709764002682934679553274041211375787728290987737659678558296436547853519299123380332169240456400489140754940131168575232148831861470368176342703663134306428168710770801893588499944601587732954236584128343788236157426418655405464250533916858794768604987782323581645860604881872980556959260551883896568987028360100444376152744950899016224929085740542359202320838219812261148906503325566494851636100567668593894561210413822464367580180144212456041537273623108397)
        beta = mpz(3862068592842769757321378472046806988247990514012376765803845418629449627462306986707538788445367295497732305603059503417264558352772865827243120560382818124525367009937613731425969213450511866538833294051568368773750856503890853841208098264379202517214715625920550870851614611230522555851923504875210868089853874796766569772450277599499864263705025477092720641698141071782570770804229258858844892443756625033077237810425262848217560566765710902307747173654197514922090707326230967462498980084965153140327872553511222005022733035669135172282202587324132848848644212850205346520456019356720203799998089371530824132913731558863027254446855793504781106417385250291502556180891324662105429433741177912446451885034691517529799089384018719170927341115059557246075757677917836934066494112515052735988495923999677497628079510204712217340554806033401000788604311627308719965727008665281375572335808008342855648187826920722276633786977430006008414692047952868918715964229841749663738415649528585513407117626540886693815197092622119570316752103764695840875211525205368225189831830033067594739589369208963452508767324524054023351628098473956338458634041717327008918932652741494107833220859806413832564286174604039574022926717319287295468834014142366609103677936413724380437992260212528306267603853969039068749983563928168931615089443202722074560035034594599191559821273742539329962366760618959815256004783386503385186957363992936680892858630389095143263374424642830203672280583516591413554883282978701496688617171074445701353817708624265416567569055340784159787717571887076240977665438058934438363544898322275501027722476970789023302841568508046866987434849844307190519218832614555425335080696412611392173215935763745115883079135078837859134582645721615637950868987330995329694969764376346063300710034475436481899526483464661608864839416444315112132658692478870973729447807737136827091888958293790730505038243513504464302462214583217688762620911451367484793083946717669791424151998731714696811012603494764350212827294963508867327640456629692076591534961241108812890140967959201344624798765142101300391873629707411894465481516898792135535538582762159705371875433485262203)
        
        print(len(alpha))
        print(len(beta))
        # Safety check
        if gmpy2.gcd(alpha, p_minus_1) != 1 or gmpy2.gcd(beta, p_minus_1) != 1:
            raise ValueError("Failed to generate coprime parameters")
        

        # Precompute frequently used values
        beta_inv = self.cached_invert(beta, p_minus_1)
        h = powmod(g, beta, p)
        e_gg_alpha = powmod(g, alpha, p)
        
        # Store precomputed values for reuse
        self.precomputed_values = {
            'g_powers': {},  # Will store g^x mod p for common exponents
            'h_powers': {},  # Will store h^x mod p for common exponents
            'small_inverses': {}  # Will store inverses of small numbers
        }
        
        # Precompute small powers and inverses for common operations
        for i in range(2, min(100, int(p_minus_1))):
            if gmpy2.gcd(i, p_minus_1) == 1:
                try:
                    self.precomputed_values['small_inverses'][i] = invert(i, p_minus_1)
                    self.precomputed_values['g_powers'][i] = powmod(g, i, p)
                    self.precomputed_values['h_powers'][i] = powmod(h, i, p)
                except:
                    continue  # Skip if inverse doesn't exist
        
        print(f"Parameter generation: {(time.perf_counter() - param_start)*1000:.0f}ms")
        
        public_key = {
            'g': g, 'h': h, 'e_gg_alpha': e_gg_alpha, 'p': p,
            'p_minus_1': p_minus_1
        }
        master_key = {
            'alpha': alpha, 'beta': beta, 'beta_inv': beta_inv
        }
        
        return public_key, master_key

    
    def keygen(self, public_key, master_key, attributes):
        """Optimized key generation with robust error handling"""
        p = public_key['p']
        g = public_key['g']
        alpha = master_key['alpha']
        p_minus_1 = public_key['p_minus_1']
        beta_inv = master_key['beta_inv']
        
        start = time.perf_counter()
        
        # Generate r with coprimality guarantee
        max_attempts = 1000
        for attempt in range(max_attempts):
            r = mpz(random.randrange(2, int(p_minus_1)))
            if gmpy2.gcd(r, p_minus_1) == 1:
                break
        else:
            raise ValueError("Failed to generate coprime r")
        
        # Optimized computation using precomputed beta_inv
        alpha_plus_r = add(alpha, r)
        exponent = mul(alpha_plus_r, beta_inv) % p_minus_1
        D = powmod(g, exponent, p)
        
        # Process attributes with better error handling
        Dj = {}
        Dj_prime = {}
        
        for attr in attributes:
            try:
                # Get hash value (guaranteed to be coprime with p-1)
                hash_val = self.hash_to_zp(attr, p)
                
                # Compute modular inverse
                hash_inv = self.cached_invert(hash_val, p_minus_1)
                
                # Compute key components
                r_hash_inv = mul(r, hash_inv) % p_minus_1
                
                Dj[attr] = powmod(g, r_hash_inv, p)
                Dj_prime[attr] = powmod(g, hash_inv, p)
                
            except ValueError as e:
                print(f"Error processing attribute '{attr}': {e}")
                # Use fallback method
                hash_val = mpz(2)
                while gmpy2.gcd(hash_val, p_minus_1) != 1:
                    hash_val += 1
                
                hash_inv = invert(hash_val, p_minus_1)
                r_hash_inv = mul(r, hash_inv) % p_minus_1
                
                Dj[attr] = powmod(g, r_hash_inv, p)
                Dj_prime[attr] = powmod(g, hash_inv, p)
        
        print(f"Key generation: {(time.perf_counter() - start)*1000:.0f}ms")
        
        return {'D': D, 'Dj': Dj, 'Dj_prime': Dj_prime, 'attributes': set(attributes)}
    
    def encrypt(self, public_key, message, policy_attrs):
        """Optimized encryption with minimal redundant operations"""
        p = public_key['p']
        g = public_key['g']
        h = public_key['h']
        e_gg_alpha = public_key['e_gg_alpha']
        p_minus_1 = public_key['p_minus_1']
        
        start = time.perf_counter()
        
        # Efficient message conversion with bounds checking
        message_bytes = message.encode('utf-8')
        if len(message_bytes) * 8 >= p.bit_length():
            max_bytes = (p.bit_length() - 8) // 8
            raise ValueError(f"Message too large. Max {max_bytes} bytes, got {len(message_bytes)}")
        
        message_int = mpz(int.from_bytes(message_bytes, byteorder='big'))
        
        # Standard random generation
        s = mpz(random.randrange(2, int(p_minus_1)))
        while gmpy2.gcd(s, p_minus_1) != 1:
            s = mpz(random.randrange(2, int(p_minus_1)))
        
        # Core encryption with optimized operations
        mask = powmod(e_gg_alpha, s, p)
        C = mul(message_int, mask) % p
        C_prime = powmod(g, s, p)
        
        # Optimize policy attribute processing
        policy_list = list(policy_attrs)
        
        # Precompute h^s once for all attributes
        h_to_s = powmod(h, s, p)
        
        # Batch compute attribute hashes and their products with s
        attr_hashes = []
        s_hash_products = []
        
        for attr in policy_list:
            hash_val = self.hash_to_zp(attr, p)
            attr_hashes.append(hash_val)
            s_hash_products.append(mul(s, hash_val) % p_minus_1)
        
        # Batch compute g^(s*H_j) for all attributes
        bases_cj_prime = [g] * len(s_hash_products)
        results_cj_prime = self.batch_powmod(bases_cj_prime, s_hash_products, p)
        
        # Construct result dictionaries
        Cj = {}
        Cj_prime = {}
        for attr in policy_list:
            Cj[attr] = h_to_s  # Same for all attributes
            Cj_prime[attr] = results_cj_prime[g]  # All computed with same base
        
        print(f"Encryption: {(time.perf_counter() - start)*1000:.0f}ms")
        
        return {
            'policy': set(policy_attrs),
            'C': C,
            'C_prime': C_prime,
            'Cj': Cj,
            'Cj_prime': Cj_prime,
            's': s,
            'length': len(message_bytes)
        }
    
    def decrypt(self, public_key, ciphertext, secret_key, master_key):
        """Ultra-optimized direct decryption"""
        start = time.perf_counter()
        
        # Fast policy satisfaction check
        if not ciphertext['policy'].issubset(secret_key['attributes']):
            print("Access Denied: Policy not satisfied")
            return None
        
        p = public_key['p']
        s = ciphertext['s']
        C = ciphertext['C']
        e_gg_alpha = public_key['e_gg_alpha']
        
        # Direct decryption - most efficient approach
        mask = powmod(e_gg_alpha, s, p)
        mask_inv = self.cached_invert(mask, p)
        message_int = mul(C, mask_inv) % p
        
        # Optimized message reconstruction
        try:
            length = ciphertext['length']
            message_bytes = int(message_int).to_bytes(length, byteorder='big')
            result = message_bytes.decode('utf-8')
            
            print(f"Decryption: {(time.perf_counter() - start)*1000:.1f}ms")
            return result
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None


def generate_cpabe_keypair(key_name="cpabe_key"):
    cpabe = CPABEOptimized()

    # Hardcoded attribute and policy (Doctor only)
    pub_key, master_key = cpabe.setup()
    secret_key = cpabe.keygen(pub_key, master_key, ["Doctor"])

    # Return all necessary parts in a dictionary like your other keys
    return {
        f"{key_name}_public": pub_key,
        f"{key_name}_master": master_key,
        f"{key_name}_secret": secret_key,
        f"{key_name}_attributes": ["Doctor"]
    }

def serialize_cpabe_ciphertext(ciphertext_dict):
    safe_dict = {}
    for k, v in ciphertext_dict.items():
        if isinstance(v, set):
            safe_dict[k] = list(v)
        elif isinstance(v, dict):
            safe_dict[k] = {ik: int(iv) for ik, iv in v.items()}
        elif hasattr(v, 'denominator'):  # gmpy2 mpz
            safe_dict[k] = int(v)
        else:
            safe_dict[k] = v
    return json.dumps(safe_dict)

def deserialize_cpabe_ciphertext(json_str):
    raw = json.loads(json_str)
    # Convert values back to mpz if needed
    for k in ['C', 'C_prime', 's']:
        if k in raw:
            raw[k] = mpz(raw[k])
    for k in ['Cj', 'Cj_prime']:
        if k in raw:
            raw[k] = {ik: mpz(iv) for ik, iv in raw[k].items()}
    raw['policy'] = set(raw.get('policy', []))
    return raw

import zlib
def cpabe_encryption(patient, write_to_nfc, preloaded_keys=None, key_name="cpabe_key"):
    cpabe = CPABEOptimized()
    patient_id = patient.get("patient_id")

    # Convert patient dict to plaintext string
    patient.pop("_id", None)
    plaintext = ",".join(str(v) for v in patient.values())

    # Load keys
    pub_key = preloaded_keys.get(f"{key_name}_public")
    policy = preloaded_keys.get(f"{key_name}_attributes", ["Doctor"])

    # Encrypt
    ciphertext = cpabe.encrypt(pub_key, plaintext, policy)

    # Serialize ciphertext dict as string (you’ll define your own format or use JSON)
    ciphertext_serialized = serialize_cpabe_ciphertext(ciphertext).encode("utf-8")
    compressed = zlib.compress(ciphertext_serialized)
    
    print("Compressed length:", len(compressed), "bytes")
    query = {"patient_id": patient_id}
    update = {
        "$set": {
            "compressed_ciphertext": compressed,
            "patient_id": patient_id  # store it explicitly
        }
    }
    result = ciphertext_collection.update_one(query, update, upsert=True)

    # Fetch the document's _id
    if result.upserted_id:  # newly inserted
        doc_id = str(result.upserted_id)
    else:  # existing document was updated
        doc = ciphertext_collection.find_one({"patient_id": patient_id})
        doc_id = str(doc["_id"])
    
    write_to_nfc(doc_id.encode())

    return doc_id, {f"{key_name}_public": pub_key,
    f"{key_name}_master": preloaded_keys.get(f"{key_name}_master"),
    f"{key_name}_secret": preloaded_keys.get(f"{key_name}_secret"),
    f"{key_name}_attributes": policy}


def cpabe_decryption(config_func, read_from_nfc, patient_id, preloaded_keys=None, key_name="cpabe_key"):
    cpabe = CPABEOptimized()

    pub_key = preloaded_keys.get(f"{key_name}_public")
    master_key = preloaded_keys.get(f"{key_name}_master")
    secret_key = preloaded_keys.get(f"{key_name}_secret")

    print("Loaded CP-ABE keys:", preloaded_keys)
    print("Public key:", preloaded_keys.get("cpabe_key_public"))
    print("Master key:", preloaded_keys.get("cpabe_key_master"))
    print("Secret key:", preloaded_keys.get("cpabe_key_secret"))

    # Read the MongoDB document ID from the NFC
    doc_id = read_from_nfc().decode()

    # Load compressed ciphertext from MongoDB
    doc = ciphertext_collection.find_one({"_id": ObjectId(doc_id)})
    if not doc:
        print(f"Ciphertext with ID {doc_id} not found in MongoDB.")
        return None
    
    # Read and decompress from NFC
    compressed = doc["compressed_ciphertext"]
    decompressed = zlib.decompress(compressed).decode("utf-8")
    ciphertext = deserialize_cpabe_ciphertext(decompressed)

    return cpabe.decrypt(pub_key, ciphertext, secret_key, master_key)


# 3072
# p = mpz("4205982594123685278729936093736292088121919083099753208813891806339423018456420375440864764652558053793305164090947384223673914129231526841350627916779051775820918141642908623152242524835689742080347303547159095378630526259849810037981119545566274503655090253763769302276955359440505765588454562025999778535616082202265378704260029630813762281612537972458241533608019881643780886638293376148858351704957676665030312436971566819625809035443989456222785398466083219383372827025485224687259610207760042872191960398284344812607865230402888342101839974696849331930694453882414677358935124557142212214093239199969749698539901629933809494938173124855773285391785805440213638157576632875027875459606770005960992204069529621691015988048673530359344355940632024098188474386072081886600124245499586242931827349691621352956984302307898517214798272857203259957684194116086310455833957511345353895757606127196995743079349538338944974795503")

# print(len(p))
# p_minus_1 = p - 1

# print(f"Prime generation: {(time.perf_counter() - start)*1000:.0f}ms")

# param_start = time.perf_counter()

# # Use fixed small generator for consistency and speed
# g = mpz(2)

# # Read alpha and beta from files
# alpha = mpz("5515498645624564675263042579002741123329130600039092456649730727729763561267662509468121903874877065693460000145959551235249645502278976730244317702597378749149785091521766124063023251280280297761996391172918612743820335400815148392388387509024844106241796177920988995657769724879759432035687385205485062304886984982950853744935871146331807966793120182326234711388167514945825032563411649984768703438845581847273732617894456448812631728174120737088674147621872614512362537488736890642017403723843988211138229365534372857488133865375248650065350089283655560028736941093020889936657272756630709890264304481629693556826566463237018597963912771185470075207485891269408643039858530906515143716727566291482760293160336095873553795709194605234898185546483369261288061305196700894311605374922253568483784842625774299334884135596792487386240213281446668669894352055801291234497797284471378060358484083484729411726435002243594731537239")

# beta = mpz("2996870730476219420188169573820838085305044555530826148735300754240361598438728560381033577756725217822293178636754524524188993858606268722931161876040928417339298003041820168914905454248689940354710260255324969050173457943603148600728540004908568003580271387992145935995256814728943315061650361379071675873565702734361426640919331632896599886332241914972930420634431349423924743631956645956956300890209647793673718710947661530493925271497761185782933642369766911817132023696557225741713751984665091835403056717414783171952609354351986360086719737543886447954163451512235893576156036106875844483250872323352438760067846299534070029766810266677776562215946881541541796425523643684647353775022286602850218718547511516859004364589125005860482427290234049193456172104513735240625939516010438013314978320009906963190182511356254638271595626140189113618107423548038607273494753833498092365323468296048665513579131274944098076834447")
# print(len(alpha))
# print(len(beta))
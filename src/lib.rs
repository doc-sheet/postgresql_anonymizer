
use pgrx::pgrx_macros::extension_sql_file;
use pgrx::prelude::*;
use pgrx::PgSqlErrorCode::*;

mod compat;
mod dummy;
mod error;
mod guc;
mod input;
mod label_providers;
mod macros;
mod masking;
mod random;
mod re;

// Load the SQL functions AFTER the rust functions
extension_sql_file!("../sql/anon.sql", finalize);

pgrx::pg_module_magic!();


//----------------------------------------------------------------------------
// Internal Functions
//----------------------------------------------------------------------------


/// Apply masking rules to a COPY statement
/// In a COPY statement, substitute the masked relation by its masking view
///
/// For instance, the statement below :
///   COPY person TO stdout;
///
/// will be replaced by :
///   COPY (
///       SELECT firstname AS firstname,
///              CAST(NULL AS text) AS lastname
///       FROM person
///   ) TO stdout;
///
/// Arguments:
/// * `pstmt` is the utility statement
/// * `policy` is the masking policy to apply
///
fn pa_rewrite_utility(pstmt: &PgBox<pg_sys::PlannedStmt>, policy: String) {
    let command_type = pstmt.commandType;
    assert!(command_type == pg_sys::CmdType_CMD_UTILITY);

    unsafe {
        if pgrx::is_a(pstmt.utilityStmt, pg_sys::NodeTag::T_ExplainStmt)
        || pgrx::is_a(pstmt.utilityStmt, pg_sys::NodeTag::T_TruncateStmt)
        {
            ereport!(ERROR, ERRCODE_INSUFFICIENT_PRIVILEGE, "role is masked");
        }
    }

    if unsafe { pgrx::is_a(pstmt.utilityStmt, pg_sys::NodeTag::T_CopyStmt) } {
        debug1!("Anon: COPY found");
        // The utilityStmt is provided as a pointer to a generice Node
        // But we now know that this Node is a CopyStmt
        // So we cast the Node pointer as a CopyStmt pointer to access the
        // CopyStmt properties
        //
        // see https://doxygen.postgresql.org/structCopyStmt.html
        //
        let mut copystmt = unsafe {
            PgBox::from_pg( pstmt.utilityStmt as *mut pg_sys::CopyStmt )
        };
        debug3!("Anon: copystmt before = {:#?}", copystmt );

        // ignore `COPY FROM` statements
        if copystmt.is_from { return; }

        // ignore `COPY (SELECT ...) TO` statements
        if copystmt.relation.is_null() {
            ereport!(ERROR, ERRCODE_FEATURE_NOT_SUPPORTED, "not implemented yet");
        }

        // We now know this is a `COPY xxx TO ...` statement

        // Fetch the relation id
        let relid = unsafe {
            pg_sys::RangeVarGetRelidExtended(
                copystmt.relation,
                pg_sys::AccessShareLock as i32,
                0,
                None,
                core::ptr::null_mut(),
            )
        };

        // Replace the relation by the masking subquery */
        copystmt.relation = core::ptr::null_mut();
        copystmt.attlist = core::ptr::null_mut();
        copystmt.query = masking::stmt_for_table(relid, policy);

        debug3!("Anon: copystmt after = {:#?}", copystmt);

        // Return the pointer to Postgres
        copystmt.into_pg();
    }
}


//----------------------------------------------------------------------------
// External Functions
//----------------------------------------------------------------------------

// All external functions are defined in the anon schema

#[pg_schema]
mod anon {
    use pgrx::prelude::*;
    use pgrx::PgSqlErrorCode::*;
    use std::ffi::CStr;
    use std::ffi::CString;
    use crate::masking;

    use crate::dummy;
    use crate::random;
    use fake::Fake;
    use fake::locales::*;

    //------------------------------------------------------------------------
    // Dummy Functions
    //------------------------------------------------------------------------

    // Address
    use fake::faker::address::raw::*;
    dummy::declare_l10n_fn_String!(dummy_city_prefix,CityPrefix);
    dummy::declare_l10n_fn_String!(dummy_city_suffix,CitySuffix);
    dummy::declare_l10n_fn_String!(dummy_city_name,CityName);
    dummy::declare_l10n_fn_String!(dummy_country_name,CountryName);
    dummy::declare_l10n_fn_String!(dummy_country_code,CountryCode);
    dummy::declare_l10n_fn_String!(dummy_street_suffix,StreetSuffix);
    dummy::declare_l10n_fn_String!(dummy_street_name,StreetName);
    dummy::declare_l10n_fn_String!(dummy_timezone,TimeZone);
    dummy::declare_l10n_fn_String!(dummy_state_name,StateName);
    dummy::declare_l10n_fn_String!(dummy_state_abbr,StateAbbr);
    dummy::declare_l10n_fn_String!(dummy_secondary_address_type,SecondaryAddressType);
    dummy::declare_l10n_fn_String!(dummy_secondary_address,SecondaryAddress);
    dummy::declare_l10n_fn_String!(dummy_zip_code,ZipCode);
    dummy::declare_l10n_fn_String!(dummy_post_code,PostCode);
    dummy::declare_l10n_fn_String!(dummy_building_number,BuildingNumber);
    dummy::declare_l10n_fn_String!(dummy_latitude,Latitude);
    dummy::declare_l10n_fn_String!(dummy_longitude,Longitude);
    //dummy::declare_l10n_fn_String!(dummy_Geohash(precision: u8);

    // Administrative
    use fake::faker::administrative::raw::*;
    dummy::declare_french_fn_String!(dummy_health_insurance_code,HealthInsuranceCode);

    // Automotive
    use fake::faker::automotive::raw::*;
    dummy::declare_french_fn_String!(dummy_licence_plate,LicencePlate);

    // Barcode
    use fake::faker::barcode::raw::*;
    dummy::declare_l10n_fn_String!(dummy_isbn,Isbn);
    dummy::declare_l10n_fn_String!(dummy_isbn13,Isbn13);

    // Color
    use fake::faker::color::raw::*;
    dummy::declare_l10n_fn_String!(dummy_hex_color,HexColor);
    dummy::declare_l10n_fn_String!(dummy_rgb_color,RgbColor);
    dummy::declare_l10n_fn_String!(dummy_rgba_color,RgbaColor);
    dummy::declare_l10n_fn_String!(dummy_hsl_color,HslColor);
    dummy::declare_l10n_fn_String!(dummy_hsla_color,HslaColor);
    dummy::declare_l10n_fn_String!(dummy_color,Color);

    // Company
    use fake::faker::company::raw::*;
    dummy::declare_l10n_fn_String!(dummy_company_suffix,CompanySuffix);
    dummy::declare_l10n_fn_String!(dummy_company_name,CompanyName);
    dummy::declare_l10n_fn_String!(dummy_buzzword,Buzzword);
    dummy::declare_l10n_fn_String!(dummy_buzzword_middle,BuzzwordMiddle);
    dummy::declare_l10n_fn_String!(dummy_buzzword_tail,BuzzwordTail);
    dummy::declare_l10n_fn_String!(dummy_catchphrase,CatchPhase);
    dummy::declare_l10n_fn_String!(dummy_bs_verb,BsVerb);
    dummy::declare_l10n_fn_String!(dummy_bs_adj,BsAdj);
    dummy::declare_l10n_fn_String!(dummy_bs_noun,BsNoun);
    dummy::declare_l10n_fn_String!(dummy_bs,Bs);
    dummy::declare_l10n_fn_String!(dummy_profession,Profession);
    dummy::declare_l10n_fn_String!(dummy_industry,Industry);

    // Creditcard
    use fake::faker::creditcard::raw::*;
    dummy::declare_l10n_fn_String!(dummy_credit_card_number,CreditCardNumber);

    // Currency
    use fake::faker::currency::raw::*;
    dummy::declare_l10n_fn_String!(dummy_currency_code,CurrencyCode);
    dummy::declare_l10n_fn_String!(dummy_currency_name,CurrencyName);
    dummy::declare_l10n_fn_String!(dummy_currency_symbol,CurrencySymbol);

    // Filesystem
    use fake::faker::filesystem::raw::*;
    dummy::declare_l10n_fn_String!(dummy_file_path,FilePath);
    dummy::declare_l10n_fn_String!(dummy_file_name,FileName);
    dummy::declare_l10n_fn_String!(dummy_file_extension,FileExtension);
    dummy::declare_l10n_fn_String!(dummy_dir_path,DirPath);

    // Finance
    use fake::faker::finance::raw::*;
    dummy::declare_l10n_fn_String!(dummy_bic,Bic);
    dummy::declare_l10n_fn_String!(dummy_isin,Isin);

    // HTTP
    use fake::faker::http::raw::*;
    dummy::declare_l10n_fn_String!(dummy_rfc_status_code,RfcStatusCode);
    dummy::declare_l10n_fn_String!(dummy_valid_statux_code,ValidStatusCode);

    // Internet
    use fake::faker::internet::raw::*;
    dummy::declare_l10n_fn_String!(dummy_free_email_provider,FreeEmailProvider);
    dummy::declare_l10n_fn_String!(dummy_domain_suffix,DomainSuffix);
    dummy::declare_l10n_fn_String!(dummy_free_email,FreeEmail);
    dummy::declare_l10n_fn_String!(dummy_safe_email,SafeEmail);
    dummy::declare_l10n_fn_String!(dummy_username,Username);
    //dummy::declare_l10n_fn_with_range_to_string!(dummy_password,Password);
    //dummy::declare_l10n_fn_String!(dummy_Password(len_range: Range<usize>);
    dummy::declare_l10n_fn_String!(dummy_ipv4,IPv4);
    dummy::declare_l10n_fn_String!(dummy_ipv6,IPv6);
    dummy::declare_l10n_fn_String!(dummy_ip,IP);
    dummy::declare_l10n_fn_String!(dummy_mac_address,MACAddress);
    dummy::declare_l10n_fn_String!(dummy_user_agent,UserAgent);

    // Lorem
    use fake::faker::lorem::raw::*;
    dummy::declare_l10n_fn_String!(dummy_word,Word);
    dummy::declare_l10n_fn_with_range_to_string!(dummy_words,Words);
    //dummy::declare_l10n_fn_with_range_to_string!(dummy_sentence,Sentence);
    //dummy::declare_l10n_fn_with_range_to_string!(dummy_sentences,Sentences);

    // Person
    use fake::faker::name::raw::*;
    dummy::declare_l10n_fn_String!(dummy_first_name,FirstName);
    dummy::declare_l10n_fn_String!(dummy_last_name,LastName);
    dummy::declare_l10n_fn_String!(dummy_title,Title);
    dummy::declare_l10n_fn_String!(dummy_suffix,Suffix);
    dummy::declare_l10n_fn_String!(dummy_name,Name);
    dummy::declare_l10n_fn_String!(dummy_name_with_title,NameWithTitle);

    // Phone Number
    use fake::faker::phone_number::raw::*;
    dummy::declare_l10n_fn_String!(dummy_phone_number,PhoneNumber);
    dummy::declare_l10n_fn_String!(dummy_cell_number,CellNumber);

    // UUID
    use fake::uuid::*;
    dummy::declare_fn_String!(dummy_uuidv1,UUIDv1);
    dummy::declare_fn_String!(dummy_uuidv3,UUIDv3);
    dummy::declare_fn_String!(dummy_uuidv4,UUIDv4);
    dummy::declare_fn_String!(dummy_uuidv5,UUIDv5);


    //------------------------------------------------------------------------
    // Random Functions
    //------------------------------------------------------------------------

    // Time

    // Random functions must be marked PARALLEL RESTRICTED because they access
    // a backend-local state that the system cannot synchronize across workers.
    // https://www.postgresql.org/docs/current/parallel-safety.html#PARALLEL-LABELING

    #[pg_extern(parallel_restricted)]
    pub fn random_time() -> pgrx::datum::Time { random::time() }

    #[pg_extern(parallel_restricted)]
    pub fn random_date() -> TimestampWithTimeZone { random::date() }

    #[pg_extern(parallel_restricted)]
    pub fn random_date_after(t: TimestampWithTimeZone)
        -> TimestampWithTimeZone { random::date_after(t) }

    #[pg_extern(parallel_restricted)]
    pub fn random_date_before(t: TimestampWithTimeZone)
        -> TimestampWithTimeZone { random::date_before(t) }

    #[pg_extern(parallel_restricted)]
    pub fn random_date_between(
        start: TimestampWithTimeZone,
        end: TimestampWithTimeZone
    ) -> TimestampWithTimeZone { random::date_between(start,end) }

    #[pg_extern(parallel_restricted)]
    pub fn random_in_daterange(r: Range<pgrx::Date>) -> Option<pgrx::Date>
    { random::date_in_daterange(r)}

    #[pg_extern(parallel_restricted)]
    pub fn random_in_tsrange(r: Range<Timestamp>) -> Option<Timestamp>
    { random::date_in_tsrange(r)}

    #[pg_extern(parallel_restricted)]
    pub fn random_in_tstzrange(r: Range<TimestampWithTimeZone>)
        -> Option<TimestampWithTimeZone>
    { random::date_in_tstzrange(r)}

    // Random Numbers

    // BIGINT
    #[pg_extern(parallel_restricted)]
    pub fn random_bigint() -> Option<i64>
    { random::bigint(Range::<i64>::new(i64::MIN,i64::MAX)) }

    #[pg_extern(parallel_restricted)]
    pub fn random_in_int8range(r: Range<i64> ) -> Option<i64>
    { random::bigint(r) }

    // +1 because the stop parameter is inclusive
    // but the range upper bound is exclusive
    #[pg_extern(parallel_restricted)]
    pub fn random_bigint_between( start: i64, stop: i64 ) -> Option<i64>
    { random::bigint(Range::<i64>::new(start,stop+1)) }

    // INT
    #[pg_extern(parallel_restricted)]
    pub fn random_int() -> Option<i32>
    { random::int(Range::<i32>::new(i32::MIN,i32::MAX)) }

    #[pg_extern(parallel_restricted)]
    pub fn random_in_int4range(r: Range<i32> ) -> Option<i32>
    { random::int(r) }

    // +1 because the stop parameter is inclusive
    // but the range upper bound is exclusive
    #[pg_extern(parallel_restricted)]
    pub fn random_int_between( start: i32, stop: i32 ) -> Option<i32>
    { random::int(Range::<i32>::new(start,stop+1)) }

    #[pg_extern(parallel_restricted)]
    pub fn random_number_with_format(format: &'static str) -> String
    { random::number_with_format(format) }

    // FLOATS

    #[pg_extern(parallel_restricted)]
    pub fn random_double_precision() -> Option<f64>
    {
        let r: Range<AnyNumeric> = Range::<AnyNumeric>::new(
            AnyNumeric::try_from(f64::MIN).unwrap(),
            AnyNumeric::try_from(f64::MAX).unwrap()
        );
        random::double_precision(r)
    }

    #[pg_extern(parallel_restricted)]
    pub fn random_in_numrange(r: Range<AnyNumeric> ) -> Option<AnyNumeric>
    { random::numeric(r) }

    #[pg_extern(parallel_restricted)]
    pub fn random_real() -> Option<f32>
    {
        let r: Range<AnyNumeric> = Range::<AnyNumeric>::new(
            AnyNumeric::try_from(f32::MIN).unwrap(),
            AnyNumeric::try_from(f32::MAX).unwrap()
        );
        random::real(r)
    }

    // PHONE
    #[pg_extern(parallel_restricted)]
    pub fn random_phone() -> String
    { random::number_with_format("0#########") }

    #[pg_extern(parallel_restricted)]
    pub fn random_phone_with_format(format: &'static str) -> String
    { random::number_with_format(format) }

    #[pg_extern(parallel_restricted)]
    pub fn random_zip() -> String
    { random::number_with_format("#####") }

    // Strings
    #[pg_extern(parallel_restricted)]
    pub fn random_string( r: Range<i32>) -> Option<String>
    { random::string(r) }

    //------------------------------------------------------------------------
    // Masking engine
    //------------------------------------------------------------------------

    /// Decorate a value with a CAST function
    ///
    /// Example: the value `1` will be transformed into `CAST(1 AS INT)`
    ///
    /// * value is the value to transform
    /// * atttypid is the id of the type for this data
    ///
    #[pg_extern]
    pub fn cast_as_regtype(value: String, atttypid: pg_sys::Oid) -> String {
        let type_be = unsafe { CStr::from_ptr(pg_sys::format_type_be(atttypid)) }
            .to_str()
            .unwrap();
        format!("CAST({value} AS {type_be})")
    }

    /// Given a function call (e.g. 'anon.fake_city()'), return the namespace
    /// the function (e.g. 'anon') if possible
    ///
    /// * returns the schema name if the function is properly schema-qualified
    /// * returns an empty string if we can't find the schema name
    ///
    /// We're calling the parser to split the function call into a "raw parse tree".
    /// At this stage, there's no way to know if the schema does really exists. We
    ///  simply deduce the schema name as it is provided.
    ///
    #[pg_extern]
    pub fn get_function_schema(function_call: String) -> String {
        if function_call.is_empty() {
            ereport!(
                ERROR,
                ERRCODE_INVALID_NAME,
                format!("function call is empty")
            );
        }
        // build a simple SELECT statement and parse it
        let query_string = format!("SELECT {function_call}");
        let query_c_string = CString::new(query_string.as_str()).unwrap();
        let raw_parsetree_list = unsafe {
            crate::compat::raw_parser(
                query_c_string.as_c_str().as_ptr() as *const pgrx::ffi::c_char
            )
        };

        // walk through the parse tree, down to the FuncCall node (if present)
        let raw_stmt = unsafe {
            // this is the equivalent of the linitial_node C macro
            // https://doxygen.postgresql.org/pg__list_8h.html#a213ac28ac83471f2a47d4e3918f720b4
            PgBox::from_pg(
                pg_sys::pgrx_list_nth(raw_parsetree_list, 0)
                as *mut pg_sys::RawStmt
            )
        };

        let stmt = unsafe {
            PgBox::from_pg( raw_stmt.stmt as *mut pg_sys::SelectStmt )
        };

        let restarget = unsafe {
            PgBox::from_pg(
                pg_sys::pgrx_list_nth(stmt.targetList, 0)
                as *mut pg_sys::ResTarget
            )
        };

        if !unsafe { pgrx::is_a(restarget.val, pg_sys::NodeTag::T_FuncCall) } {
            ereport!(
                ERROR,
                ERRCODE_INVALID_NAME,
                format!("'{function_call}' is not a valid function call")
            );
        }

        // if the function name is qualified, extract and return the schema name
        // https://github.com/postgres/postgres/blob/master/src/include/nodes/parsenodes.h#L413
        let fc = unsafe {
            PgBox::from_pg(restarget.val as *mut pg_sys::FuncCall)
        };
        // fc.funcname is a pointer to a pg_sys::List
        let funcname = unsafe {
            PgBox::from_pg(fc.funcname)
        };

        if funcname.length == 2 {
            // the function name is qualified, the first element of the list
            // is the schema name
            let schema_val = unsafe {
                PgBox::from_pg(
                    pg_sys::pgrx_list_nth(funcname.as_ptr(), 0)
                    as *mut crate::compat::SchemaValue
                )
            };
            let schema_c_ptr = unsafe{crate::compat::strVal(*schema_val)};
            let schema_c_str = unsafe {CStr::from_ptr(schema_c_ptr)};
            return schema_c_str.to_str().unwrap().to_string();
        }

        // found nothing, so return an empty string
        "".to_string()
    }

    /// For a given role, returns the policy in which he/she is masked
    /// or the NULL if the role is not masked.
    ///
    /// * roleid is the id of the user we want to mask
    ///
    #[pg_extern]
    pub fn get_masking_policy(roleid: pg_sys::Oid) ->  Option<String> {
        // Possible Improvement : allow masking rule inheritance by checking
        // also the roles that the user belongs to
        // This may be done by using `roles_is_member_of()` ?

        for policy in list_masking_policies() {
            if has_mask_in_policy(roleid,policy.unwrap()) {
                return Some(policy.unwrap().to_string());
            }
        }

        // Found nothing, return NULL
        None
    }

    /// Check that a role is masked in the given policy
    ///
    #[pg_extern]
    pub fn has_mask_in_policy(
        roleid: pg_sys::Oid,
        policy: &'static str
    ) -> bool {
        use crate::re;
        use crate::masking;

        if let Some(seclabel) = masking::rule(
            pg_sys::AuthIdRelationId,
            roleid,
            0,
            policy
        ){
            if seclabel.is_null() { return false; }

            let seclabel_cstr = unsafe {
                CStr::from_ptr(seclabel.as_ptr())
            };
            // return true is the security label is `MASKED`
            return re::is_match_masked(seclabel_cstr);
        }

        false
    }

    ///
    /// Initialize the extension
    ///
    /// /!\ this function was called `anon_init` in the C implementation
    ///
    #[pg_extern]
    pub fn init_masking_policies() -> bool {
        // For some reasons, this can't be done int PG_init()
        for _policy in list_masking_policies().iter() {
            Spi::run("SECURITY LABEL FOR anon ON SCHEMA anon IS 'TRUSTED'")
                .expect("SPI Failed to set schema anon as trusted");
        }

        true
    }

    /// Return all the registered masking policies
    ///
    /// NOTE: we can't return a Vec<Option<String>> here because it seems that
    /// `register_label_provider(...)` needs a &'static str
    ///
    /// TODO: `SplitGUCList` from varlena.h is not available in PGRX 0.11
    ///
    #[pg_extern]
    pub fn list_masking_policies() -> Vec<Option<&'static str>> {
        // transform the GUC (CStr pointer) into a Rust String
        let masking_policies = crate::guc::ANON_MASKING_POLICIES.get()
                              .unwrap().to_str().expect("Should be a string");

        // remove the white spaces
        //masking_policies.retain(|c| !c.is_whitespace());

        if masking_policies.is_empty() {
            ereport!(
                ERROR,
                ERRCODE_NO_DATA,
                "Anon: the masking policy is not defined"
            );
        }

        return masking_policies.split(',').map(Some).collect();
    }

    /// Returns the "select clause filters" that will mask the authentic data
    /// of a table for a given masking policy
    ///
    #[pg_extern]
    pub fn masking_expressions_for_table(
        relid: pg_sys::Oid,
        policy: String
    ) -> String {
        let lockmode = pg_sys::AccessShareLock as i32;
        // `pg_sys::relation_open()` will raise XX000
        // if the specified oid isn't a valid relation
        let relation = unsafe {
            PgBox::from_pg(pg_sys::relation_open(relid, lockmode))
        };
        // reldesc is a TupleDescData object
        // https://doxygen.postgresql.org/structTupleDescData.html
        let reldesc = unsafe { PgBox::from_pg(relation.rd_att) };
        let natts = reldesc.natts;
        let attrs = unsafe {
            reldesc.attrs.as_slice(natts.try_into().unwrap())
        };

        let mut expressions = Vec::new();
        for a in attrs {
            if a.attisdropped {
                continue;
            }
            let filter_value = masking::value_for_att(&relation, a, policy.clone());
            let attname_quoted = masking::quote_name_data(&a.attname);
            let filter = format!("{filter_value} AS {attname_quoted}");
            expressions.push(filter);
        }

        // pass the relation back to Postgres
        unsafe {
            pg_sys::relation_close(relation.as_ptr(), lockmode);
        }

        expressions.join(", ").to_string()
    }

    /// Returns the masking filter that will mask the authentic data
    /// of a column for a given masking policy
    ///
    /// * relid is the relation OID
    /// * colnum is the attribute position, numbered from 1 up
    /// * policy is the masking policy
    ///
   #[pg_extern]
    pub fn masking_value_for_column(
        relid: pg_sys::Oid,
        colnum: i32,
        policy: String
    ) -> Option<String> {

        let lockmode = pg_sys::AccessShareLock as i32;
        // `pg_sys::relation_open()` will raise XX000
        // if the specified oid isn't a valid relation
        let relation = unsafe {
            PgBox::from_pg(pg_sys::relation_open(relid, lockmode))
        };

        // reldesc is a TupleDescData object
        // https://doxygen.postgresql.org/structTupleDescData.html
        let reldesc = unsafe { PgBox::from_pg(relation.rd_att) };
        let natts = reldesc.natts;
        let attrs = unsafe {
            reldesc.attrs.as_slice(natts.try_into().unwrap())
        };

        // Here attributes are numbered from 0 up
        let a = attrs[colnum as usize - 1 ];

        if a.attisdropped {
            return None;
        }

        let masking_value = masking::value_for_att(&relation,&a,policy);

        // pass the relation back to Postgres
        unsafe {
            pg_sys::relation_close(relation.as_ptr(), lockmode);
        }

        Some(masking_value)
    }

}

//----------------------------------------------------------------------------
// Hooks
//----------------------------------------------------------------------------

static mut HOOKS: AnonHooks = AnonHooks {
};

struct AnonHooks {
}

impl pgrx::hooks::PgHooks for AnonHooks {

    // Hook trigger for each utility commands (anything other SELECT,INSERT,
    // UPDATE,DELETE)
    fn process_utility_hook(
        &mut self,
        pstmt: PgBox<pg_sys::PlannedStmt>,
        query_string: &core::ffi::CStr,
        read_only_tree: Option<bool>,
        context: pg_sys::ProcessUtilityContext,
        params: PgBox<pg_sys::ParamListInfoData>,
        query_env: PgBox<pg_sys::QueryEnvironment>,
        dest: PgBox<pg_sys::DestReceiver>,
        completion_tag: *mut pg_sys::QueryCompletion,
        prev_hook: fn(
            pstmt: PgBox<pg_sys::PlannedStmt>,
            query_string: &core::ffi::CStr,
            read_only_tree: Option<bool>,
            context: pg_sys::ProcessUtilityContext,
            params: PgBox<pg_sys::ParamListInfoData>,
            query_env: PgBox<pg_sys::QueryEnvironment>,
            dest: PgBox<pg_sys::DestReceiver>,
            completion_tag: *mut pg_sys::QueryCompletion,
        ) -> pgrx::hooks::HookResult<()>,
    ) -> pgrx::hooks::HookResult<()> {

        use crate::anon::get_masking_policy;

        if unsafe { pg_sys::IsTransactionState() } {
            let uid = unsafe { pg_sys::GetUserId() };

            // Rewrite the utility command when transparent dynamic masking
            // is enabled and the role is masked
            if guc::ANON_TRANSPARENT_DYNAMIC_MASKING.get() {
                if let Some(masking_policy) = get_masking_policy(uid) {
                    pa_rewrite_utility(&pstmt,masking_policy);
                }
            }
        }

        // Call the previous hook (if any)
        prev_hook(
            pstmt,
            query_string,
            read_only_tree,
            context,
            params,
            query_env,
            dest,
            completion_tag,
        )
    }
}


//----------------------------------------------------------------------------
// Initialization
//----------------------------------------------------------------------------

/// _PG_init() is called when the module is loaded, not when the extension
/// is created. There is presently no way to unload a loaded module.
///
/// # Safety
///
/// The `#[pg_guard]` macro ensures that Rust `panic!()` and Postgres
/// `elog(ERROR)` are properly handled by PGRX. So even if the `extern 'C'
/// functions are declared `unsafe`, they are actually "less unsafe"  than some
/// C functions because of this guard.
///
#[pg_guard]
pub unsafe extern "C" fn _PG_init() {
    pgrx::hooks::register_hook(&mut HOOKS);
    guc::register_gucs();
    label_providers::register_label_providers();
    debug1!("Anon: extension initialized");
}


//----------------------------------------------------------------------------
// Unit tests
//----------------------------------------------------------------------------

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    pub mod fixture {
        ///
        /// # Test fixtures
        ///
        /// Create objects for testing purpose
        ///
        /// This is a very basic testing context
        /// For more sophisticated use cases, use the `pg_regress` functional
        /// test suite
        ///

        use pgrx::prelude::*;

        pub fn create_masked_role() -> pg_sys::Oid {
            Spi::run("
                CREATE ROLE batman;
                SECURITY LABEL FOR anon ON ROLE batman is 'MASKED';
            ").unwrap();
            Spi::get_one::<pg_sys::Oid>("SELECT 'batman'::REGROLE::OID;")
                .unwrap()
                .expect("should be an OID")
        }

        pub fn create_table_person() -> pg_sys::Oid {
            Spi::run("
                 CREATE TABLE person AS
                 SELECT  'Sarah'::VARCHAR(30)        AS firstname,
                         'Connor'::TEXT              AS lastname
                 ;

                 SECURITY LABEL FOR anon ON COLUMN person.lastname
                   IS 'MASKED WITH VALUE NULL';
            ").unwrap();

            Spi::get_one::<pg_sys::Oid>("SELECT 'person'::REGCLASS::OID")
                .unwrap()
                .expect("should be an OID")
        }

        pub fn create_trusted_schema() -> pg_sys::Oid {
            Spi::run("
                CREATE SCHEMA gotham;
                SECURITY LABEL FOR anon ON SCHEMA gotham is 'TRUSTED';
            ").unwrap();
            Spi::get_one::<pg_sys::Oid>("SELECT 'gotham'::REGNAMESPACE::OID;")
                .unwrap()
                .expect("should be an OID")
        }

        pub fn create_unmasked_role() -> pg_sys::Oid {
            Spi::run("
                CREATE ROLE bruce;
            ").unwrap();
            Spi::get_one::<pg_sys::Oid>("SELECT 'bruce'::REGROLE::OID;")
                .unwrap()
                .expect("should be an OID")
        }

        pub fn create_untrusted_schema() -> pg_sys::Oid {
            Spi::run("
                CREATE SCHEMA arkham;
            ").unwrap();
            Spi::get_one::<pg_sys::Oid>("SELECT 'arkham'::REGNAMESPACE::OID;")
                .unwrap()
                .expect("should be an OID")
        }
    }

    //
    // Testing external functions
    //

    #[pg_test]
    fn test_anon_cast_as_regtype() {
        use crate::anon::cast_as_regtype;
        let oid = pg_sys::Oid::from(21);
        assert_eq!( "CAST(0 AS smallint)",
                    cast_as_regtype('0'.to_string(),oid));
    }

    #[pg_test]
    fn test_anon_get_function_schema() {
        use crate::anon::get_function_schema;
        assert_eq!("a",get_function_schema("a.b()".to_string()));
        assert_eq!("", get_function_schema("publicfoo()".to_string()));
    }

    #[pg_test(error = "function call is empty")]
    fn test_anon_get_function_schema_error_empty() {
        use crate::anon::get_function_schema;
        get_function_schema("".to_string());
    }

    #[pg_test(error = "'foo' is not a valid function call")]
    fn test_anon_get_function_schema_error_invalid() {
        use crate::anon::get_function_schema;
        get_function_schema("foo".to_string());
    }

    #[pg_test]
    fn test_anon_get_masking_policy() {
        use crate::anon::get_masking_policy;
        let batman = fixture::create_masked_role();
        let bruce  = fixture::create_unmasked_role();
        let expected = Some("anon".to_string());
        assert_eq!( get_masking_policy(batman), expected);
        assert!(get_masking_policy(bruce).is_none())
    }

    #[pg_test]
    fn test_anon_has_mask_in_policy() {
        use crate::anon::has_mask_in_policy;
        let batman = fixture::create_masked_role();
        let bruce  = fixture::create_unmasked_role();
        assert!( has_mask_in_policy(batman,"anon") );
        assert!( ! has_mask_in_policy(bruce,"anon") );
        assert!( ! has_mask_in_policy(batman,"does_not_exist") );
        let not_a_real_roleid = pg_sys::Oid::from(99999999);
        assert!( ! has_mask_in_policy(not_a_real_roleid,"anon") );
    }

    #[pg_test]
    fn test_anon_list_masking_policies() {
        use crate::anon::list_masking_policies;
        assert_eq!(vec![Some("anon")],list_masking_policies());
    }

    #[pg_test]
    fn test_anon_masking_expressions_for_table(){
        use crate::anon::masking_expressions_for_table;
        let relid = fixture::create_table_person();
        let policy = "anon";
        let result = masking_expressions_for_table(relid,policy.to_string());
        let expected = "firstname AS firstname, CAST(NULL AS text) AS lastname"
                        .to_string();
        assert_eq!(expected, result);
    }


    #[pg_test]
    fn test_anon_masking_value_for_column(){
        use crate::anon::masking_value_for_column;
        let relid = fixture::create_table_person();
        let policy = "anon";

        // testing the first column
        let mut result = masking_value_for_column(relid,1,policy.to_string());
        let mut expected = "firstname".to_string();
        assert_eq!(Some(expected),result);
        // testing the second column
        result = masking_value_for_column(relid,2,policy.to_string());
        expected = "CAST(NULL AS text)".to_string();
        assert_eq!(Some(expected),result);
    }

    //
    // Testing Internal functions
    //

    #[pg_test]
    #[ignore]
    fn test_pa_rewrite_utility(){
        //
        // The unit tests for pa_rewrite_utility() are a bit complex
        // to write because the function is called by the rewrite_utility hook
        // and we would have to create planned statements from scratch and
        // pass them to function.
        //
        // Alternatively, the functional tests are way simpler to write, so
        // currently we focus on them and ignore this unit test.
        //
        // See `tests/sql/copy.sql` and `test/sql/pg_dump.sql` for more details
        //
    }

}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}

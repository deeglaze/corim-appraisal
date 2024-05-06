{-# LANGUAGE UnicodeSyntax, ExistentialQuantification, GADTSyntax, RankNTypes, TypeFamilies,
    ScopedTypeVariables, TypeFamilyDependencies, StandaloneDeriving, UndecidableInstances #-}

module Appraisal (IRName, CBOR,cborlookup ) where

--import Data.Bits
--import Data.ByteString as B
--import Data.Hashable
--import Data.HashMap.Strict as H
--import Data.String.UTF8
--import Data.UUID
--import Data.Word
--import Network.URI

class (Eq a) => PartialOrd a where
  leq :: a -> a -> Bool

-- A type of maps where all keys are discretely compared with =, and
-- the range is compared with the range type.
-- data DiscreteMap d r where
--   DiscreteMap :: (Hashable d, PartialOrd r) => (H.HashMap d r) -> DiscreteMap d r

type IRName = Either String Integer

-- https://www.iana.org/assignments/named-information/named-information.xhtml
type IANANamedInfo = Either String Integer

-- type DigestsType = DiscreteMap IANANamedInfo B.ByteString
-- type Digest = (IANANamedInfo, B.ByteString)

data CBOR = CInt !Integer -- major type 0, 1, and tags 2,3 all represent some arbitrary precision integer.
--    | CBstr !ByteString -- major type 2
--    | CUtf8 !ByteString -- !(UTF8 ByteString) -- major type 3
    | CSeq ![CBOR] -- major type 4
    | CMap !CBORMap -- major type 5
--    | CTag Word64 ByteString
    | CBool !Bool -- major type 7, value 20 (false) or value 21 (true)
    | CNull -- major type 7, value 22
    | CUndef -- major type 7, value 23
    | CFloat16 !Float -- major type 7, value 25
    | CFloat32 !Float -- major type 7, value 26
    | CFloat64 !Double -- major type 7, value 27
    | CBreak -- major type 7, value 31
    -- | CUnassignedSimple !Word8
    deriving (Eq, Show)

-- reflectDigests :: CBOR -> Digest
-- reflectDigests = undefined

-- The reflected CoRIM representation already assumes signature verification has occurred before decoding.
-- data CoRIM p = CoRIM {
--     id :: CoRIMId p,
--     tags :: (ConciseTag p) [(ConciseTag p)],
--     dependent :: [ CoRIMLocator ],
--     profile :: Maybe (ProfileId p),
--     -- validity unmodeled.
--     entities :: [ (CoRIMEntity p) ],
--     extensions :: [ (ProfileCorimTop p) ]
-- }

data CoMID p = CoMID {}
--   midLanguage :: Maybe String
--   midId :: TagId
--   midEntities :: [CoMIDEntity p]
--   ? &(entities: 2) => [ + comid-entity-map ]
--   ? &(linked-tags: 3) => [ + linked-tag-map ]
--   &(triples: 4) => triples-map
--   * $$concise-mid-tag-extension
-- }

-- data ProfileId p = ProfileURI String | ProfileProfileId (ProfileProfileId p)

-- data CoRIMRole p where
--   ManifestCreator :: CoRIMRole p
--   ProfileRole :: ProfileCoRIMRoleExt p -> CoRIMRole p
  
-- data Entity p r ext = EntityName (EntityName p)
--   | RegId (Maybe URI)
--   | EntityRole [r]
--   | EntityExtensions [ext]

-- data EntityName p = EntityText String | ProfileEntityName (ProfileEntityName p)

-- type CoRIMEntity p = Entity p (CoRIMRole p) (ProfileCoRIMEntityExt p)

-- data CoRIMId p = ProfileText String
--     | ProfileUUID !UUID
--     | ProfileCorimId (ProfileCorimId p)

-- data ConciseTag p where
--     TagSWID :: ConciseTag p -- unmodeled
--     TagMid :: CoMID p -> ConciseTag p
--     TagBOM :: ConciseTag p -- unmodeled
--     ProfileConciseTag :: ProfileConciseTag p -> ConciseTag p

-- data CoRIMLocator = CoRIMLocator {
--     href :: URI, -- uri
--     thumbprint :: Maybe Digest
-- }

-- encodeCBOR :: CBOR -> ByteString
-- encodeCBOR = undefined

type CBORMap = [(CBOR, CBOR)]

cborlookup :: CBORMap -> CBOR -> Maybe CBOR
cborlookup [] _ = Nothing
cborlookup ((k,v):cs) k'
  | k == k'   = Just v
  | otherwise = cborlookup cs k'





-- -- All of this is I think semantics preserving with the current document but helps me conceptualize it better.
-- --
-- -- ## Some CoRIM triples do not have any semantics.
-- --
-- -- As a means of conveying information about target environments that manufacturers, platform providers, etc would like to ship as claimed information, there are triples that are "just a common name for a common thing and maybe you should try to use that before rolling your own".
-- -- I don't know why these exist without at least a few real examples of organizations that desire them to have standard allocations for them.
-- --
-- --   * attestation key triple
-- --   * device identity triple
-- --   * domain dependency triple
-- --   * domain membership triple
-- --   * coswid triples
-- --
-- -- After some form of ingestion, this information can be made available to policy engines to do with what they will. There is no impact on required actions for appraising evidence.
-- --
-- -- ## CoRIM defines elements of policy
-- --
-- -- A manifest is an enumeration of what exists.
-- -- A reference integrity manifest is an expectation of what should exist, with support for integrity checks.
-- -- "Should" is policy, and "exists" comes with a procedure for determining existence (or not, for fiat triples).
-- -- Triples are a directive to add to "what is known of the target environment", which the document calls the "accepted claim set" (ACS).
-- -- The conditions under which to do so are its primitive semantics given a limited API to query the current state of appraisal.
-- --
-- -- Policy decides which triples to allow to add to the ACS.
-- -- I think the truth of the matter is that a triple's interaction with accepted claims is as an executor of policy.
-- -- Policy is then how many triples from a knowledge base should execute on the ACS, and how often while not yet at a fixed point.
-- -- Pretty much the whole initialization of the verifier knowledge base from CoRIMs is to use everything from the CoRIM during execution unless (rather manually?) told not to in some bespoke way–e.g., a specific endorsement is actually a security bug and needs to be held back in production until a new CoRIM gets issued.
-- --
-- -- Policy is a composition of CoRIM elements–CoRIM encodes pieces of policy.
-- -- Evidence appraisal is a recommended semantics for policy that uses CoRIM documents for its knowledge base.
-- -- The theory of operation then is an interaction between a policy engine and a representation of accepted claims.
-- --
-- -- ## Appraisal as abstract machine
-- --
-- -- The ACS punning the CoRIM data representation hurts my comprehension.
-- -- I see its purpose as a means to answer specific questions about what is known of the target environment and to then make a policy decision to add to what is known.
-- -- Let's say instead that for the purposes of defining the semantics of triples, we have access to a limited conceptual API that evolves a state machine.
-- --
-- -- At the end of interpreting triples in an abstract machine, the verifier then has a finalization step that translates "what is known" to an attestation result format.
-- -- The translation can add and drop things as per its policy, but that is outside the scope of CoRIM.
-- --
-- -- Evidence must be reflected into some form that the API can describe, and reusing CoRIM triples for this is dangerous due to scope creep from runtime back to issuance time.
-- -- The way that a profile is expected to reflect evidence into a triple-map (initializing the ACS) confuses verifier state with API and CoRIM.
-- --
-- -- The actual state versus expected state should be different types to highlight their phase distinction between issuing a CoRIM and interpreting evidence with the help of a body of policy pieces as encoded in CoRIMs.
-- --
-- -- ### Machine interactions
-- --
-- -- The API is simple because the triples that have a defined semantics are simple to express with it.
-- -- "Triples" are now more than 3 things given that authorization is part of the picture, and the profile for the triple is relevant.

-- class ACS m where
--     -- If the assertion introduces a conflict, then the interaction is a failure.
--     -- `p` represents extras added by the profile.
--     -- Uses of assert can be ordered in any way, but interactions with `query` will not commute.
--     -- The behavior one should expect is that eventually assert will indicate that nothing new was learned from every execution of all triples.
--     -- The Bool result is true iff assert increased the knowledge lattice.
--     -- The new state after an assert is the second element of the returned tuple.
--     assert :: forall p. Profile p => p -> Predicate p -> m -> ((Either Bool AssertFailure), m)

--     -- Does the known state imply the given predicate holds?
--     -- If not, the result is some report of failure.
--     -- If so, who authorized that state if anyone?
--     -- We could also make a less enumerative version that can answer for a specific authorizer, but keeping this simple for the model.
--     query :: forall p. Profile p => p -> Predicate p -> m -> (Either (Authorization p) QueryFailure)

-- -- Failure is uninterpreted for the abstract machine.
-- -- It can be "No", it can be or "No because constraints x, y, z, didn't match", or whatever.
-- data AssertFailure = AFailure String
-- data QueryFailure = QFailure String

-- data Authorization p = Authorization [ CryptoKey p ]

-- type ClaimKey = Int
-- data Predicate p = Profile p => Claim (SubEnvironment p) ClaimKey (Authorization p) (Object p)

-- data SubEnvironment p = Profile p => SubEnvironment {
--   classId :: Maybe (ClassId p),
--   instanceId :: Maybe (InstanceId p),
--   groupId :: Maybe (GroupId p),
--   componentId :: Maybe (MeasuredElement p)
-- }

-- newtype UEID = UEID B.ByteString deriving Eq
-- newtype OID = OID [ Integer ] deriving Eq

-- data GroupId p = GroupUUID UUID | GroupBytes B.ByteString | GroupProfile (ProfileGroupId p)
-- instance (Profile p) => PartialOrd (GroupId p) where
--   leq g g' = g == g'
-- deriving instance (Profile p) => Eq (GroupId p)

-- data ClassId p = ClassOID OID | ClassUUID UUID | ClassBytes B.ByteString | ClassProfile (ProfileClassId p)
-- instance (Profile p) => PartialOrd (ClassId p) where
--   leq c c' = c == c'
-- deriving instance (Profile p) => Eq (ClassId p)

-- data InstanceId p = InstanceUEID UEID | InstanceUUID UUID | InstanceKey (CryptoKey p) | InstanceBytes B.ByteString | InstanceProfile (ProfileInstanceId p)
-- instance (Profile p) => PartialOrd (InstanceId p) where
--   leq i i' = i == i'
-- deriving instance (Profile p) => Eq (InstanceId p)

-- data MeasuredElement p = MeasuredOID OID | MeasuredUUID UUID | MeasuredInt Int | MeasuredProfile (ProfileMeasuredElement p)
-- instance (Profile p) => PartialOrd (MeasuredElement p) where
--   leq m m' = m == m'
-- deriving instance (Profile p) => Eq (MeasuredElement p)
-- deriving instance (Profile p) => Eq (SubEnvironment p)

-- -- where at least one of class/instance/group is not Nothing

-- -- `assert` is the means of augmenting the ACS, and `query` is the means of matching it.
-- -- The semantics of selecting authorizers makes `query` a bit more than a <= relation.
-- --
-- -- The `claim` alternate of the `Fact` type is only referencing the map keys of `measurement-values-map`, since all the appraisal is about endorsements and reference values, both of which are only about `measurement-values-map`.
-- -- Since we're talking about endorsements, reference values, and evidence, I conceptualize this all better with the term of "Claim", but even that is overloaded, since a "Claim Set" for JWT or CWT has a much more centralized meaning.
-- --
-- -- Why `SubEnvironment`?
-- -- I don't really understand what made `mkey` a necessary part of `measurement-map` instead of `environment-map`, and the document calls it a reference to a sub-environment, so I'm taking it back into the subject and out of the object.
-- --
-- -- A machine state is either the set of prior assertions or a failure state indicating that the assertions in combination imply false.
-- -- Prior assertions form a knowledge base that is nearly a lattice component-wise, but `Authorization` does not form a lattice as it is not partially ordered.
-- --

-- -- A `Profile` is a type class for all the profile extension points

-- -- from corim-map
-- -- type family ProfileConciseTag p = r | r -> p -- $concise-tag-type-choice
-- -- type family ProfileCorimId p = r | r -> p -- $corim-id-type-choice
-- -- type family ProfileProfileId p = r | r -> p -- $profile-type-choice
-- -- type family ProfileCorimTop p = r | r -> p -- $$corim-map-extension
-- -- -- from corim-entity-map
-- -- type family ProfileCoRIMEntityExt p = r | r -> p -- $$corim-entity-map-extension
-- -- type family ProfileCoRIMRoleExt p = r | r -> p
-- -- type family ProfileEntityName p = r | r -> p -- $entity-name-type-choice
--   -- -- from corim-signer-map
--   -- type ProfileSignerExt p = r | r -> p -- $$corim-signer-map-extension
--   -- -- from concise-mid-tag
--   -- type ProfileCoMid p = r | r -> p -- $$concise-mid-type-extension
--   -- type ProfileTagId p = r | r -> p -- $tag-id-type-choice
--   -- -- from comid-entity-map
--   -- type ProfileCoMidRole p = r | r -> p -- $comid-role-type-choice
--   -- -- from linked-tag-map in concise-mid-tag
--   -- type ProfileTagRel p = r | r -> p -- $tag-rel-type-choice
--   -- from environment-map
--   -- If Nothing, the profile rejects the representation. If Just Nothing, then it accepts the standard representation.
--   -- If Just (Just o), then we have a ProfileDefined o.
--   -- Default behavior is to accept the standard representation without additional reflections.

-- class (Eq (ProfileClassId p), Eq (ProfileInstanceId p), Eq (ProfileGroupId p),
--       Eq (ProfileMeasuredElement p), Eq (ProfileCryptoKey p), Eq (ProfileVersionScheme p),
--       Eq (ProfileDomain p), PartialOrd (ProfileObject p)) => Profile p where
--   type family ProfileClassId p = r | r -> p -- $class-id-type-choice
--   type family ProfileInstanceId p = r | r -> p -- $instance-id-type-choice
--   type family ProfileGroupId p = r | r -> p -- $group-id-type-choice
--   -- from measurement-map
--   type family ProfileMeasuredElement p = r | r -> p -- $measured-element-type-choice
--   -- from triples-map
--   --  type ProfileTriple p -- $$triples-map-extension
--   -- from flags-map in triples-map
--   type ProfileFlagExt p = r | r -> p -- $$flags-map-extension
--   -- from many places
--   type family ProfileCryptoKey p = r | r -> p -- $crypto-key-type-choice
--   -- from measured-values-map
--   type ProfileRawValue p -- $raw-value-type-choice
--   type ProfileVersionScheme p -- $version-scheme
--   type ProfileDomain p -- $domain-type-choice
--   type family ProfileObject p = r | r -> p -- $$measurement-values-map-extension

--   profileReflectCryptoIdKey :: CBOR -> Maybe (Maybe (ProfileCryptoKey p))
--   profileReflectCryptoIdKey _ = Just Nothing
--   -- profileReflectTriple :: Int -> CBOR -> Maybe (Maybe (ProfileTriple p))
--   --  profileReflectTriple _ _ = Just Nothing
--   profileReflectClassId :: CBOR -> Maybe (Maybe (ProfileClassId p))
--   profileReflectClassId _ = Just Nothing
--   profileReflectGroupId :: CBOR -> Maybe (Maybe (ProfileGroupId p))
--   profileReflectGroupId _ = Just Nothing
--   profileReflectInstanceId :: CBOR -> Maybe (Maybe (ProfileInstanceId p))
--   profileReflectInstanceId _ = Just Nothing
--   profileReflectMeasuredElement :: CBOR -> Maybe (Maybe (ProfileMeasuredElement p))
--   profileReflectMeasuredElement _ = Just Nothing
--   profileReflectMeasuredValue :: Int -> CBOR -> Maybe (Maybe (ProfileObject p))
--   profileReflectMeasuredValue _ _ = Just Nothing

-- -- ### Order relation

-- -- For Maybe, Nothing is <= anything, and Just-wrapped items have to be compared.
-- instance (PartialOrd o) => PartialOrd (Maybe o) where
--     leq Nothing _ = True
--     leq (Just a) (Just a') = a `leq` a'

-- -- SubEnvironment is point-wise ordered.
-- instance (Profile p) => PartialOrd (SubEnvironment p) where
--     leq (SubEnvironment c i g p) (SubEnvironment c' i' g' p') = and [c `leq` c', i `leq` i', g `leq` g', p `leq` p']

-- -- `CBORvalue` is ordered by [STD94](https://ietf-rats-wg.github.io/draft-ietf-rats-corim/draft-ietf-rats-corim.html#STD94) deterministic CBOR encoding equality, so that's any of the `$`[...]`-type-choice` fields above.

-- -- `Object` is an open-ended type of comparable values that can be extended by profiles when reflecting negative keys, and by new standards.
-- --
-- -- `Authorization` in a `Query` has a "one of" semantics rather than an "all of" semantics, so its comparisons for stateful environments do not form a preorder (non-transitive).
-- -- For example `[a,b] <= [a, c]` and `[a,c] <= [c]` but `[a,b]` is incomparable to `[c]`. 
-- --
-- -- The informal description of the core property of the abstract machine is that `query(predicate)` should only return a positive result if the machine is not in a fail state and prior assertions imply `Predicate`.
-- -- The contents of the result should only be a set of the authorizers that asserted predicates that imply the queried predicate.
-- -- An important note is that queries are only of atomic facts, so a query has to be wholly and independently implied by individual previous assertions.
-- -- Multiple assertions just mean more authorizers.
-- --
-- -- Before I can define the core axiom of the system, I need to describe a bit more what I understand of the setup.


-- -- ### CoRIM triples reflection into `Predicate`

-- -- The `reference-triple-record`, `endorsed-triple-record`, `stateful-environment-record`, etc all are describing different ways of referencing a set of claims, and they all have an `environment-map` and `measurement-map`.
-- -- My understanding is that the `authorized-by` field of measurement-map should not be used outside of a stateful-environment-record to condition on who has authorized a particular claim.
-- -- The reason being the authorization for the contained measurements is already defined to be the CoRIM issuer.
-- -- To assign a different authorization to a triple without a valid signature is a security flaw.

-- -- We translate a pair of `environment-map` and `measurement-map` into a set of `Predicate` with the following procedure:
-- --
-- -- For each key `k => v` in the `measurement-values-map`, construct a new `Predicate` for the set by
-- --
-- -- if `k` is negative, create a `vendor` alternate with the profile id of the CoRIM containing the triple, otherwise create a `standard` alternate.
-- --   * `environment-map` / `class` to `Fact` / `Claim` / `SubEnvironment` / `Class` as `Some(class)` if present, otherwise `None`
-- --   * `environment-map` / `instance` to `Fact` / `Claim` / SubEnvironment / `Instance` as `Some(instance)` if present, otherwise `None`
-- --   * `environment-map` / `group` to `Fact` / `Claim` / `SubEnvironment` / `Group` as `Some(group)` if present, otherwise `None`
-- --   * `measurement-map` / `mkey` to `Predicate` / `SubEnvironment` / `Component` as `Some(mkey)` if present, otherwise `None`.
-- --   * `k` to `Fact` / `Claim` / `claim-key`
-- --   * `measurement-map` / `authorized-by` to `Fact` / `Claim` / `Authorization`
-- --   * `v` to `reflect(profile, measurement-values-map, k, v)` where `reflect` is a metafunction to be defined since raw CBOR representation in the context of the claim key (and profile) can impact how the value should be interpreted going forward.
-- --     The whole map has to be there as an argument because of the semantics chosen for the `raw-value` and `raw-value-mask` representation.
-- --
-- -- If `k` is negative, the meaning of `reflect` is profile-defined, and then therefore the matching semantics that correspond to the newly reflected data kind if indeed new.
-- -- If `k` is not negative and the right hand side has type extensions not defined in the profile and not in the standard, then that also uses a profile-defined reflection operation.



-- -- #### The `reflect` metafunction
-- --
-- -- Where there are different CBOR tags to assign specific "matching semantics" to particular values, there exist analogous abstract representations of values that act as objects of a meet-semilattice that can "match" through an ordering relation.
-- --
-- -- If you're to assign this metafunction a type, let's say

-- reflect :: (Profile p) => [Object p] -> Int -> CBOR -> Object p
-- reflect = undefined

-- -- The `Object` type is open for extension by profile, though standardization can help de-duplicate, avoid collisions for names of concepts, unify, etc.
-- --
-- -- The Object type of the CoRIM document today is

-- data Object p where
--   Top :: Object p
--   Bot :: Object p
--   CBOREnc :: B.ByteString -> Object p
--   Svn :: Integer -> Object p
--   MinSvn :: Integer -> Object p
--   Digests :: DigestsType -> Object p
--   IRs :: DiscreteMap IRName DigestsType -> Object p
--   CryptoKeys :: [ CryptoKey p ] -> Object p
--   PR167 :: B.ByteString -> B.ByteString -> Object p
--   ProfileObject :: ProfileObject p -> Object p

-- deriving instance (Profile p) => Eq (Object p)


-- -- `CBOR(bytes)`: the common case is exact equality of deterministic CBOR binary representation.
-- -- `Svn(u)`: exact value of a security version number, and `u` is a non-negative integer.
-- -- `MinSvn(u)`: a value below which doesn't match, where `u` is a non-negative integer.
-- -- `Digests(digest-type)`: a crypto-agile representation of a single value, but hashed with multiple algorithms. The CDDL `digest-type` is exactly what's needed, though it can be in a native data format.
-- -- `IRs(integrity-registers)`: map of name to digests
-- -- `CryptoKeys(list[$crypto-key-type-choice])`: No idea. Seems too specific.
-- -- `PR167(bytes, bytes)`: PR#167 has some words for this as "raw value" but its proposed semantics is a bit too specific for the name. The length of the second bytes must be greater than or equal to the length of the first bytes.
-- -- Top: Any
-- -- Bottom: Conflict


-- -- The restriction on `Object` is that meet (⊓) must be computable.
-- -- If any combination of assertions is impossible, that must lead to an appraisal failure.
-- --
-- -- With types defined, let's define `reflect`:


-- -- reflect(_, _, &(svn: 1), #6.552(u)) = svn(reflectUint(u))
-- -- reflect(_, _, &(svn: 1), #6.553(u)) = minSvn(reflectUint(u))
-- -- reflect(_, _, &(digests: 2), d) = reflectDiscreteMap(reflectIANANamedInfo, ReflectBytes, d)
-- -- reflect(_, m, &(raw-value: 4), #6.560(b)) = pr167(ReflectBytes(b), [0xff]*BytesLen(b)) if m / &(raw-value-mask: 5) is not present.
-- --   else PR167(ReflectBytes(b), reflectBytes(cborMapLookup(m, 5)))
-- -- reflect(_, _, _, o) = CBOR(cbor_encode(o)) -- otherwise, though flags and version probably should have different semantics defined.

-- -- reflect(_, _, &(cryptokeys: 13), keys) = cryptoKeys([reflectKey(k) for k in reflectCBORList(keys)])
-- -- reflect(_, _, &(integrity-registers: 14), i) = reflectIRs(i)
 
-- -- Since we have some discrete maps, I have a generic metafunction that pointwise reflects a CBOR map into a DiscreteMap.

-- reflectDiscreteMap :: (PartialOrd r) => (CBOR -> d) -> (CBOR -> r) -> CBORMap -> DiscreteMap d r
-- reflectDiscreteMap = undefined


-- -- ### Order relations: `Object` ≤

-- -- Objects are used in Assert and Query. Query is a check for implication from a prior Assert, and Assert requires a check for bottom (⊥) after meet.
-- --
-- -- First of all, every alternate is pairwise incomparable except `Svn` and `MinSvn`. Take `≤` to be the reflexive transitive closure of the following rules

-- instance (Profile p) => PartialOrd (Object p) where
--     -- ------ [Top]
--     -- o ≤ ⊤
--     leq _ Top = True

--     -- ------- [Bottom]
--     -- ⊥ ≤ o
--     leq Bot _ = True

--     -- v ≤ v'
--     -- ------------------- [MinSvn-Svn]
--     -- MinSvn(v) ≤ Svn(v')
--     leq (MinSvn v) (Svn v') = v <= v'

--     -- v ≤ v'
--     -- ---------------------- [MinSvn-MinSvn]
--     -- MinSvn(v) ≤ MinSvn(v')
--     leq (MinSvn v) (MinSvn v') = v <= v'

--     -- ∀alg. alg ∈ dom(d) => d(alg) = d'(alg)
--     -- -------------------------------------- [Digest containment]
--     -- Digests(d) ≤ Digests(d')
--     leq (Digests d) (Digests d') = d `leq` d'

--     -- ∀name. name ∈ dom(i) => Digests(i(name)) ≤ Digests(i'(name))
--     -- ------------------------------------------------------------ [Integrity register containment]
--     -- IRs(i) ≤ IRs(i')
--     leq (IRs i) (IRs i') = i `leq` i'

--     -- l = len(m')
--     -- len(r) ≤ len(r')
--     -- bitwise_and(zero_extend(r, l), zero_extend(m, l)) = bitwise_and(r', m')
--     -- ----------------------------------------------------------------------- [PR167 match]
--     -- PR167(r,m) ≤ PR167(r',m')
--     leq (PR167 r m) (PR167 r' m') = B.length m <= l && (bitwiseand rl ml) == (bitwiseand r'l m')
--       where l = B.length m'
--             rl = (zeroextend r l)
--             ml = (zeroextend m l)
--             r'l = (zeroextend r' l)

--     -- Partial ordering of ProfileObject is a constraint on the Profile typeclass.
--     leq (ProfileObject o) (ProfileObject o') = o `leq` o'

-- -- For every k v in m, m' must have a value for k and be >= v.
-- instance PartialOrd (DiscreteMap d r) where
--   leq (DiscreteMap m) (DiscreteMap m') = foldlWithKey' (\ acc k v -> acc && (Just v) `leq` (H.lookup k m')) True m

-- instance Eq (DiscreteMap d r) where
--   (==) (DiscreteMap m) (DiscreteMap m') = foldlWithKey' (\ acc k v -> acc && (Just v) `leq` (H.lookup k m')) True m

-- -- For PR#167, a helper metafunction that zero-extends a byte array to the right with zeros up to a given length.

-- bitwiseand :: ByteString -> ByteString -> ByteString
-- bitwiseand a b = B.pack [x .&. y | (x,y) <- B.zip a b]
-- zeroextend :: ByteString -> Int -> ByteString
-- zeroextend b l = B.append b (B.pack [fromIntegral 0 | _ <- [1..(l - (B.length b))]])
-- -- it is an error if len(b) > l

-- -- -------------------------------
-- -- ### Order function: `Object` ⊓
-- -- 
-- -- Top (⊤) and bottom (⊥) have the expected semantics:


-- meet :: (Profile p) => Object p -> Object p -> Object p

-- meet Top o = o
-- meet o Top = o
-- -- Svn(v) ⊓ MinSvn(v') = if v' ≤ v then Svn(v) else ⊥
-- -- MinSvn(v') ⊓ Svn(v) = if v' ≤ v then Svn(v) else ⊥
-- -- MinSvn(v) ⊓ MinSvn(v') = MinSvn(max(v, v'))
-- meet (Svn v) (MinSvn v') | v' <= v = Svn v
-- meet (MinSvn v') (Svn v) | v' <= v = Svn v
-- meet (MinSvn v) (MinSvn v') = MinSvn (max v v')
-- -- CBOR(b) ⊓ CBOR(b) = CBOR(b)
-- meet (CBOREnc b) (CBOREnc b') | b == b' = CBOREnc b
-- meet _ _ = Bot





-- -- Digests can't conflict on shared algorithms, but they can merge algorithms not seen in the other:
-- -- ```
-- -- Digests(d) ⊓ Digests(d') = ⊥ if d ⊓ d' = ⊥ else Digests(d ⊓ d')

-- -- ⊓ for DigestType:
-- -- d ⊓ d' = ⊥ if d|b ≠ d'|b
-- --   else (λx. if x ∈ dom(d) then d(x) else d'(x))
-- --   where b = dom(d) ∩ dom(d') and | is function restriction to a domain.
-- -- ```

-- -- Integrity registers are a discrete lifting of `DigestType` ordering:

-- -- ```
-- -- IRs(i) ⊓ IRs(i') = ⊥ if i|b ⊓ i'|b = ⊥
-- --   otherwise (λx. if x ∈ b then (i(x) ⊓ i'(x)) else (if x ∈ dom(i) then i(x) else i'(x)))
-- -- ```

-- -- The meet operation must satisfy o ⊓ o' ≤ o ∧ o ⊓ o' ≤ o' to be a true meet, so I use that as a guiding design constraint.
-- -- ```
-- -- PR167(r,m) ⊓ PR167(r',m') = PR167(r,m) if PR167(r, m) ≤ PR167(r', m') ∧ PR167(r', m') ≤ PR167(r, m)
-- --   else ⊥
-- -- ```

-- -- If the result is to have any different length, then the different length needs to have no impact on the comparison since shrinking the raw value in the result would need to zero extend and still compare against values that could be non-zero.
-- -- The result could be a more compact to help normalize the representation, but the ordering semantics is the same.

-- -- For example, define `count_right_zeros` to return how many bytes we can trim on the right because the `bitwise_and` of `r` and `m` is zero there, and then remove a suffix of that length from `r` and `m[:len(r)]`.

-- -- ## Triples as instructions for the abstract machine

-- -- The interpretation of every triple from a CoRIM signed by a key k is then a specific direction for how to use query and assert.
-- --
-- -- A program is a set of triples closed by their signing key and profile.
-- -- A triple decomposed to individual claims and closed by its signing key(s) and profile is defined as a Predicate.
-- -- To allow for multiple triples of different profiles to co-exist, we define an instruction as an existential packing of Profile type with the Predicate.

-- data Instr where
--     Instr :: Profile a => a -> Predicate a -> Instr

-- -- compile translates a CoRIM document into a sequence of instructions for the abstract machine.
-- -- compile :: CoRIM -> [Instr]
-- -- compile = undefined

-- -- The execution of a program is a non-deterministic but confluent calculation of a fixed point.
-- -- The CoRIM spec does not prescribe an execution strategy for quick convergence.
-- --
-- -- The signing key representation is not semantically relevant apart from decidable equality.
-- -- I'll simplify here and just say it's a string.
-- -- The CoRIM spec does not prescribe a program construction process from a bundle of CoRIM documents.
-- --
-- -- Here is a sketch of a simplified form of program construction from a set of CoRIM documents.
-- -- For each CoRIM, determine its profile and signing key.
-- -- If the profile is trusted (i.e., implemented) then we have a type for it with an Profile type class instance.
-- -- 
-- -- we add to the program every interpreted triple from every CoMID tag as signed CoRIM and associating each triple with its profile and authorizer, we get the profile from the corim-map.

-- -- The COSE_Sign1 for the signed CoRIM has protected headers that hint at the cose-key-type, but don't have a direct representation.
-- -- The relevant protected headers in the CoRIM's COSE_Sign1 are alg and kid.
-- -- The rest of the COSE_Key is in the certificate for kid: kty, key_ops, base IV.


-- -- ### Endorsement triple semantics

-- -- An endorsement-triple can be interpreted as an `Assert` for each `Predicate` the triple represents (broken down by claim key and environment-map associated with each) with the key of the triple's CoRIM issuer.

-- -- ### MEC-endorsement semantics

-- -- Represent each stateful-environment-map as a collection of {Predicate...}. If all(Query(Predicate) = Left(_) for Predicate in {Predicate...}) then for each Predicate the RHS represents, Assert(Predicate, k) for MEC triple CoRIM issuer k.

-- -- ### Reference triple semantics

-- -- A reference-triple from CoRIM issuer k can be interpreted as, for each Predicate it represents, if `Query(Predicate) = Left(_)`, then Assert(Predicate, k).

-- -- It's important to note that this is piecemeal and not all-or-nothing. If you want all-or-nothing semantics, you can have an MEC-endorsement that duplicates the reference values on both the left and right hand side.

-- -- There is no comparison with the attestation key from the Query! Presumably the attestation key is checked before asserting the reflected predicate from evidence, and otherwise endorsements of the same claim are not asserted from the knowledge base without some policy that checks verified evidence.

-- -- ### State initialization

-- -- Similar to CoRIM triples needing to be reflected into a pattern language for matching evidence, evidence must be reflected into the language of values that patterns operate on.

-- -- The initialization step to translate evidence into starting knowledge sounds to me like wanting a standard representation for evidence, I'll make the jump to instead say that when looking at a CMW as the input form of evidence, the Content media type is what should drive the semantics of translating evidence into starting claims. Saying the CoRIM's profile is what interprets the evidence is not an appropriate interpretation of measured boot technologies. There are multiple CoRIMs that make up the knowledge base. A predicate about solid fact-of-the-matter from evidence is different from a predicate with fuzzier meaning, such as some function returns true on the value representing the payload of a particular claim key.

-- -- A "candidate entry" as used from the document is a claim without authorization from a key you like. It may start of with the attestation key authorizing it as claimed from a trusted manufacturer's measurement hardware, but the value itself may not yet have the further authorization you want.

-- -- The document specifies partial matching of EMT environments against known state, so we have a containment relation for states that is the comparison operation.

-- -- ## Environment containment

-- -- > A stateful environment environment-map is a subset of an ACS entry environment-map if each field (for example class, instance etc.) which is present in the stateful environment environment-map is also present in the ACS entry, and the CBOR encoded field values in the stateful environment and ACS entry are binary identical. If a field is not present in the stateful environment environment-map then the presence of, and value of, the corresponding ACS entry field does not affect whether the environment-maps are subsets.

-- -- In notation I understand, I'll say,`sub ⊑ sup` or `EnvironmentMatch(sub, sup)`

-- -- ```
-- -- def EnvironmentMatch(sub, sup):
-- --   return all(cbor_encoding_equal(getattr(sub, a), getattr(sup, a, IllegalValue)) for a in dir(sub))
-- -- ```

-- -- ### Axioms of the abstract machine

-- -- An abstract machine state is represented by its list of Asserted predicates, and a Query is in the context of prior assertions.

-- -- ```
-- -- ..., Predicate_n ⊢ False
-- -- ------------------------------------------------------ [conflict]
-- -- ..., Assert(Predicate_n, k_n) ⊨ Query(Predicate) = Right(Failure)

-- -- forall i. Predicate_i ⊢ Predicate => k_i in A
-- -- forall k in A. exists j. Predicate_j ⊢ Predicate
-- -- A nonempty
-- -- ------------------------------------------------------ [inference]
-- -- ..., Assert(Predicate_n, k_n) ⊨ Query(Predicate) = Left(A)
-- -- ```

-- -- Predicate implication is limited to specific claims to limit to the standardized matching semantics of representable evidence.

-- -- ```
-- -- sub ⊑ sup                    match(q, a)
-- -- ----------------------------------------------------------
-- -- standard[sup, claim-key, a] |- standard[sub, claim-key, q]
-- -- ```

-- -- -- # Appendix
-- -- --
-- -- -- Metafunctions that have remaining definitions but should be clearer in the context of their presentation to not need the whole definition upfront.


-- -- The DICE profile is the unit profile.
-- instance Profile () where
--   type instance ProfileClassId () = ()
--   type instance ProfileInstanceId () = ()
--   type instance ProfileGroupId () = ()
--   type instance ProfileMeasuredElement () = ()
--   type ProfileFlagExt () = ()
--   type instance ProfileCryptoKey () = ()
--   type instance ProfileRawValue () = ()
--   type instance ProfileVersionScheme () = ()
--   type instance ProfileDomain () = ()
--   type instance ProfileObject () = ()
--   -- Associated types for the DICE profile are empty.

-- data CryptoKey p = Meh String | ProfileCryptoKey (ProfileCryptoKey p)
-- deriving instance (Eq (ProfileCryptoKey p)) => Eq (CryptoKey p)
-- instance PartialOrd () where
--   leq () () = True

# premium unlock
> compressed
```regex
(is|has|go)\w*_?(vip|premiu|purcha|subscri|pro|activ|points?|expir|renew|loyal|bonus|gift|paid|adfree|)\w*_?(user|member|access)?|(subscription|unlocked|premium|ad_?remov|loyalty)\w*_?(status)?
```
> uncompressed
```
isvip|is_vip|vipuser|vip_user|ispro|is_pro|isprouser|ispro_user|ispremium|is_premium|ispremiumuser|ispremium_user|alreadyvip|already_vip|ispurchased|is_purchased|unlocked|adremoved|ad_removed|gopremium|go_premium|removed_ads|is_subscribed|subscribe_pro|is_activated|iseligible|is_eligible|unlockpremium|unlock_premium|isunlocked|is_unlocked|ispaid|is_paid|adfree|ad_free|isadfree|is_ad_free|isgift|is_gift|giftuser|gift_user|isgifted|is_gifted|hasgift|has_gift|premiumuser|premium_user|ispremium|is_premium|isvip|is_vip|ispro|is_pro|isactiveuser|is_active_user|ismemberuser|is_member_user|isloyal|is_loyal|loyaltystatus|loyalty_status|isloyaluser|is_loyal_user|hasloyalty|has_loyalty|loyaltypoints|loyalty_points|haspoints|has_points|pointbalance|point_balance|bonususer|bonus_user|isbonus|is_bonus|bonusactive|bonus_active|isbonususer|is_bonus_user|hasbonus|has_bonus|istrial|is_trial|trialuser|trial_user|istrialuser|is_trial_user|trialexpired|trial_expired|isexpired|is_expired|isrenewed|is_renewed|renewactive|renew_active|hasrenewed|has_renewed|ispremiumaccess|is_premium_access|premiumstatus|premium_status|ispremiumuseractive|is_premium_user_active|active_subscription|active_subscription_user|isactivepremium|is_active_premiumisvip|is_vip|vipuser|vip_user|ispro| is_pro|isprouser|ispro_user|ispremium|is_premium|ispremiumuser|ispremium_user|alreadyvip|already_vip|ispurchased|is_purchased|unlocked|adremoved|ad_removed|gopremium|go_premium|removed_ads|is_subscribed|subscribe_pro|subscriberpro|active_pack_title|SubscribePro|has_history|PREMIUM|buy_sub|vip_month|getCurrentVipMode|subscriberpro|active_pack_title|haspremium|has_premium|isactivated|is_activated|unlockpremium|unlock_premium|isgift|is_gift|giftuser|gift_user|isgifted|is_gifted|hasaccess|has_access|renewsubscription|renew_subscription|premiumaccess|premium_access|isregistered|is_registered|bonususer|bonus_userisactive|is_active|isuser|is_user|ismember|is_member|ispremiumuser|is_premium_user|isvipmember|is_vip_member|hasaccess|has_access|purchased|purchase_done|premiumaccess|premium_access|isregistered|is_registered|renewsubscription|renew_subscription|member_since|subscribed|subscription_status|haspremium|has_premium|isactivated
```

# ads removal
### general
---
search:
```regex
\.method\s+(public|private|static)\s+(?!abstract|native)\s+(.*Ad|.*(show|load)Ad.*|.*Ad(Ready|Load|Click).*)\(.*\)V
```
replace:
```$0\nreturn-void```

---
search:
```regex
\.method\s+(public|private|static)\s+(?!abstract|native)\s+(.*Ad|.*(show|load)Ad.*|.*Ad(Track|Enabl).*)\(.*\)Z
```
replace:
```$0\nconst\/4 p0, 0x1\nreturn p0```

> NOTE: *match case must be enabled*

### google ads
coming soon
